using System.Buffers.Binary;
using System.Text;

namespace NetParser;

public class ExtractPeByteCode(string pePath)
{
    private readonly byte[] _bytes = File.ReadAllBytes(pePath);
    private int _cursor;

    public void PrintIlBytecode()
    {
        SkipMsDosHeader();
        var numberOfSections = ParsePeFileHeader();
        var clrRuntimeHeaderRva = ParsePeOptionalHeader();
        var sectionHeaders = ParseSectionHeaders(numberOfSections);

        var cliHeaderOffset = RvaToFileOffset(sectionHeaders, clrRuntimeHeaderRva);
        _cursor = cliHeaderOffset;
        var metadataRva = ParseCliHeader();

        var metadataOffset = RvaToFileOffset(sectionHeaders, metadataRva);
        _cursor = metadataOffset;

        var numberOfStreams = ParseMetadataRoot();
        ParseStreamHeader(numberOfStreams, metadataRva, sectionHeaders);

        var (heapOfSetSizes, maskValid, rowCounts) = ParseTableHeader();

        var stringHeapSize = GetHeapIndexSize(heapOfSetSizes, "String");
        var guidHeapSize = GetHeapIndexSize(heapOfSetSizes, "GUID");

        SkipModule(stringHeapSize, guidHeapSize);
        SkipTypeRef(rowCounts, maskValid, stringHeapSize);
        SkipTypeDef(rowCounts, maskValid, stringHeapSize);
        var methodDefs = ParseMethodDefTable(heapOfSetSizes, rowCounts, stringHeapSize);

        PrintIlBytecode(sectionHeaders, methodDefs);
    }

    // II.25.2.1 MS-DOS header
    private void SkipMsDosHeader() => Advance(128);

    // II.25.2.2 PE file header
    private ushort ParsePeFileHeader()
    {
        Advance(6); // Skip PE Signature (2) and Machine (4)
        var numberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(GetNext(2));
        Advance(16); // Advance to the end of header

        return numberOfSections;
    }

    // II.25.2.3 PE optional header
    private uint ParsePeOptionalHeader()
    {
        Advance(28);
        Advance(68); // PE Header Windows NT-specific fields
        Advance(112); // Advance to Rva
        var metadataRva = BinaryPrimitives.ReadUInt32LittleEndian(GetNext(4));
        Advance(12); // Advance to the end of header
        return metadataRva;
    }

    // II.25.3 Section headers
    private SectionHeader[] ParseSectionHeaders(ushort numberOfSections)
    {
        var sectionHeaders = new SectionHeader[numberOfSections];

        for (var i = 0; i < numberOfSections; i++)
        {
            var name = Encoding.ASCII.GetString(GetNext(8)).Trim('\0');
            Advance(4);
            var virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(GetNext(4));
            Advance(4);
            var pointerToRawData = BinaryPrimitives.ReadUInt32LittleEndian(GetNext(4));
            Advance(16);
            sectionHeaders[i] = new SectionHeader(name, virtualAddress, pointerToRawData);
        }

        return sectionHeaders;
    }

    // II.25.3.3 CLI header
    private uint ParseCliHeader()
    {
        Advance(8);
        var rva = BinaryPrimitives.ReadUInt32LittleEndian(GetNext(4));
        Advance(52); // Advance to the end of header
        return rva;
    }

    // I.24.2.1 Metadata root
    private ushort ParseMetadataRoot()
    {
        // Signature
        // MajorVersion
        // MinorVersion
        // Reserved
        // Length
        Advance(16);

        // Number of bytes allocated to hold version string (including
        // null terminator), call this x.
        // Call the length of the string (including the terminator) m (we
        // require m <= 255); the length x is m rounded up to a multiple
        // of four.
        var versionOffset = _cursor;
        // UTF8-encoded null-terminated version string of length m (see above)
        var versionEndOffset = MoveToNextZero(versionOffset);

        var currentOffset = versionOffset + versionEndOffset - _cursor;
        _cursor = (currentOffset + 3) & ~3; // Align a number to the next multiple of 4

        Advance(2);
        var numberOfStreams = BinaryPrimitives.ReadUInt16LittleEndian(GetNext(2));
        return numberOfStreams;
    }

    // II.24.2.2 Stream header
    private void ParseStreamHeader(ushort numberOfStreams, uint metadataRva, SectionHeader[] sectionHeaders)
    {
        var streamHeaders = new StreamHeader[numberOfStreams];
        for (var i = 0; i < numberOfStreams; i++)
        {
            var streamOffset = BinaryPrimitives.ReadUInt32LittleEndian(GetNext(4));
            var size = BinaryPrimitives.ReadUInt32LittleEndian(GetNext(4));

            // Read stream name (null-terminated)
            var nameOffset = _cursor;
            var nameEndOffset = MoveToNextZero(nameOffset);
            var name = Encoding.ASCII.GetString(GetNext(nameEndOffset - nameOffset));
            var fileOffset = RvaToFileOffset(sectionHeaders, metadataRva + streamOffset);
            streamHeaders[i] = new StreamHeader(size, name, fileOffset);

            var currentOffset = nameEndOffset + 1;
            _cursor = (currentOffset + 3) & ~3; // Align a number to the next multiple of 4
        }

        var hashStream = streamHeaders.FirstOrDefault(x => x.Name == "#~");
        if (hashStream is null)
        {
            throw new Exception("Invalid file structure, #~ header is missing");
        }
    }

    // II.24.2.6 #~ stream (tables header)
    private (byte heapOfSetSizes, ulong maskValid, uint[] rowCounts) ParseTableHeader()
    {
        Advance(6);
        var heapOfSetSizes = GetNext().First();
        Advance();
        var maskValid = BinaryPrimitives.ReadUInt64LittleEndian(GetNext(8));
        Advance(8);

        // Setting bit by bit, if there is 1 that means the row is set
        var rowCounts = new uint[64];
        for (var i = 0; i < 64; i++)
        {
            if ((maskValid & (1UL << i)) != 0)
            {
                rowCounts[i] = BitConverter.ToUInt32(GetNext(4));
            }
        }

        return (heapOfSetSizes, maskValid, rowCounts);
    }

    // II.22.30 Module : 0x00
    private void SkipModule(int stringHeapSize, int guidHeapSize)
    {
        // Generation, Name, Mvid, EncId, EncBaseId
        Advance(2 + stringHeapSize + guidHeapSize * 3);
    }

    // II.22.38 TypeRef : 0x01
    private void SkipTypeRef(uint[] rowCounts, ulong maskValid, int stringHeapSize)
    {
        var typeRefRowCount = rowCounts[0x01];
        var tableIndexSize1A = GetTableIndexSize(0x1A, maskValid);
        for (var i = 0; i < typeRefRowCount; i++)
        {
            // ResolutionScope, TypeName, TypeNamespace
            Advance(tableIndexSize1A + stringHeapSize * 2);
        }
    }

    // II.22.37 TypeDef : 0x02
    private void SkipTypeDef(uint[] rowCounts, ulong maskValid, int stringHeapSize)
    {
        var typeDefRowCount = rowCounts[0x02]; // Get number of TypeDefs
        var typeDefExtendsSize = GetTableIndexSize(0x01, maskValid); // TypeRef Table size (for Extends column)
        var fieldTableIndexSize = GetTableIndexSize(0x04, maskValid); // Field Table index size
        for (var i = 0; i < typeDefRowCount; i++)
        {
            // Flags, TypeName, Typenamespace, Extends, TypDefOrRef, FieldList
            Advance(4 + 2 * stringHeapSize + typeDefExtendsSize + fieldTableIndexSize);
        }
    }

    // II.22.26 MethodDef : 0x06
    private MethodDef[] ParseMethodDefTable(byte heapOsSetSizes, uint[] rowCounts, int stringHeapSize)
    {
        var blobHeapSize = GetHeapIndexSize(heapOsSetSizes, "Blob");
        var methodDefRowCount = rowCounts[0x06]; // Number of methods
        var methodDefTable = new MethodDef[methodDefRowCount];
        for (var i = 0; i < methodDefRowCount; i++)
        {
            var rva = BinaryPrimitives.ReadUInt32LittleEndian(GetNext(4));
            methodDefTable[i] = new MethodDef(rva);
            // ImplFlags, Flags, Name, Signature, ParamList
            Advance(2 + 2 + stringHeapSize + blobHeapSize + 2);
        }

        return methodDefTable;
    }

    private void PrintIlBytecode(SectionHeader[] sectionHeaders, MethodDef[] methodDefs)
    {
        var codeSection = sectionHeaders.First(x => x.Name == ".text");
        foreach (var method in methodDefs)
        {
            var fileOffset = method.Rva - codeSection.VirtualAddress + codeSection.PointerToRawData;
            var firstByte = _bytes[fileOffset];
            var isTinyHeader = (firstByte & 0x3) == 0x2;
            var isFatHeader = (firstByte & 0x3) == 0x3;
            var codeSize = 0;
            if (isTinyHeader)
            {
                codeSize = (firstByte >> 2); // Upper 6 bits store size
            }

            var codeOffset = fileOffset + 1;

            if (isFatHeader)
            {
                codeSize = BinaryPrimitives.ReadInt32LittleEndian(_bytes.AsSpan((int)(codeOffset + 4)));
            }

            var methodEnd = codeOffset + codeSize;
            var ilString = BitConverter.ToString(_bytes.Skip((int)codeOffset).Take((int)(methodEnd - codeOffset)).ToArray());
            Console.WriteLine(ilString);
        }
    }

    private void Advance(int i = 1) => _cursor += i;

    private byte[] GetNext(int len = 1)
    {
        var bts = _bytes.Skip(_cursor).Take(len).ToArray();
        _cursor += len;
        return bts;
    }

    private int RvaToFileOffset(SectionHeader[] sectionHeaders, uint rva)
    {
        foreach (var section in sectionHeaders)
        {
            var virtualAddress = section.VirtualAddress;
            if (rva >= virtualAddress && rva < virtualAddress + virtualAddress)
            {
                return (int)(section.PointerToRawData + (rva - virtualAddress));
            }
        }

        throw new InvalidOperationException($"Could not convert RVA 0x{rva:X8} to file offset");
    }

    private int MoveToNextZero(int index)
    {
        while (_bytes[index] != 0 && index < _bytes.Length)
        {
            index++;
        }

        return index;
    }

    // The HeapSizes field is a bitvector that encodes the width of indexes into the various heaps. If bit 0 is
    // set, indexes into the “#String” heap are 4 bytes wide; if bit 1 is set, indexes into the “#GUID” heap are
    // 4 bytes wide; if bit 2 is set, indexes into the “#Blob” heap are 4 bytes wide. Conversely, if the
    // HeapSize bit for a particular heap is not set, indexes into that heap are 2 bytes wide
    private int GetHeapIndexSize(byte heapOfSetSizes, string heapType)
    {
        return heapType switch
        {
            "String" => (heapOfSetSizes & 0x01) != 0 ? 4 : 2,
            "GUID" => (heapOfSetSizes & 0x02) != 0 ? 4 : 2,
            "Blob" => (heapOfSetSizes & 0x04) != 0 ? 4 : 2,
            _ => throw new ArgumentException("Invalid heap type")
        };
    }

    private int GetTableIndexSize(int tableId, ulong maskValid)
    {
        return ((long)maskValid & (1L << tableId)) != 0 ? 4 : 2;
    }
}