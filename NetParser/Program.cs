using System.Buffers.Binary;
using System.Text;

var bytes = File.ReadAllBytes("./HelloWorld.dll");
var cursor = 0;

// II.25.2.1 MS-DOS header
Advance(128);

// II.25.2.2 PE file header
Advance(6); // Skip PE Signature (2) and Machine (4)
var numberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(GetNext(2));
Advance(16); // Advance to the end of header

// II.25.2.3 PE optional header
Advance(28);
Advance(68); // PE Header Windows NT-specific fields
Advance(112); // Advance to Rva
var clrRuntimeHeaderRva = BinaryPrimitives.ReadUInt32LittleEndian(GetNext(4));
Advance(12); // Advance to the end of header

var sectionHeaders = new SectionHeader[numberOfSections];
// II.25.3 Section headers
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

var cliHeaderOffset = RvaToFileOffset(clrRuntimeHeaderRva);
cursor = cliHeaderOffset;

// II.25.3.3 CLI header
Advance(8);
var metadataRva = BinaryPrimitives.ReadUInt32LittleEndian(GetNext(4));
Advance(52); // Advance to the end of header

var metadataOffset = RvaToFileOffset(metadataRva);
cursor = metadataOffset;

// I.24.2.1 Metadata root
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
var versionOffset = cursor;
// UTF8-encoded null-terminated version string of length m (see above)
var versionEndOffset = MoveToNextZero(versionOffset);

var currentOffset = versionOffset + versionEndOffset - cursor;
cursor = (currentOffset + 3) & ~3; // Align a number to the next multiple of 4

Advance(2);
var numberOfStreams = BinaryPrimitives.ReadUInt16LittleEndian(GetNext(2));

// II.24.2.2 Stream header
var streamHeaders = new StreamHeader[numberOfStreams];
for (var i = 0; i < numberOfStreams; i++)
{
    var streamOffset = BinaryPrimitives.ReadUInt32LittleEndian(GetNext(4));
    var size = BinaryPrimitives.ReadUInt32LittleEndian(GetNext(4));

    // Read stream name (null-terminated)
    var nameOffset = cursor;
    var nameEndOffset = MoveToNextZero(nameOffset);
    var name = Encoding.ASCII.GetString(GetNext(nameEndOffset - nameOffset));
    var fileOffset = RvaToFileOffset(metadataRva + streamOffset);
    streamHeaders[i] = new StreamHeader(size, name, fileOffset);

    currentOffset = nameEndOffset + 1;
    cursor = (currentOffset + 3) & ~3; // Align a number to the next multiple of 4
}

var hashStream = streamHeaders.FirstOrDefault(x => x.Name == "#~");
if (hashStream is null)
{
    return;
}

// II.24.2.6 #~ stream (tables header)
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

var stringHeapSize = GetHeapIndexSize("String");
var guidHeapSize = GetHeapIndexSize("GUID");

// II.22.30 Module : 0x00
// Generation, Name, Mvid, EncId, EncBaseId
Advance(2 + stringHeapSize + guidHeapSize * 3);

// II.22.38 TypeRef : 0x01
var typeRefRowCount = rowCounts[0x01];
var tableIndexSize1A = GetTableIndexSize(0x1A);
for (var i = 0; i < typeRefRowCount; i++)
{
    // ResolutionScope, TypeName, TypeNamespace
    Advance(tableIndexSize1A + stringHeapSize * 2);
}

// II.22.37 TypeDef : 0x02
var typeDefRowCount = rowCounts[0x02]; // Get number of TypeDefs
var typeDefExtendsSize = GetTableIndexSize(0x01); // TypeRef Table size (for Extends column)
var fieldTableIndexSize = GetTableIndexSize(0x04); // Field Table index size
for (var i = 0; i < typeDefRowCount; i++)
{
    // Flags, TypeName, Typenamespace, Extends, TypDefOrRef, FieldList
    Advance(4 + 2 * stringHeapSize + typeDefExtendsSize + fieldTableIndexSize);
}

// II.22.26 MethodDef : 0x06
var blobHeapSize = GetHeapIndexSize("Blob");
var methodDefRowCount = rowCounts[0x06]; // Number of methods
var methodDefTable = new MethodDef[methodDefRowCount];
for (var i = 0; i < methodDefRowCount; i++)
{
    var rva = BinaryPrimitives.ReadUInt32LittleEndian(GetNext(4));
    methodDefTable[i] = new MethodDef(rva);
    // ImplFlags, Flags, Name, Signature, ParamList
    Advance(2 + 2 + stringHeapSize + blobHeapSize + 2);
}

// Extract IL
var codeSection = sectionHeaders.First(x => x.Name == ".text");
foreach (var method in methodDefTable)
{
    var fileOffset = method.Rva - codeSection.VirtualAddress + codeSection.PointerToRawData;
    var firstByte = bytes[fileOffset];
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
        codeSize = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan((int)(codeOffset + 4)));
    }

    var methodEnd = codeOffset + codeSize;
    var ilString = string.Join("", bytes.Skip((int)codeOffset).Take((int)(methodEnd - codeOffset)).Select(x => x.ToString("X")));
    Console.WriteLine(BitConverter.ToString(bytes.Skip((int)codeOffset).Take((int)(methodEnd - codeOffset)).ToArray()));
}

return;

int GetTableIndexSize(int tableId)
{
    return ((long)maskValid & (1L << tableId)) != 0 ? 4 : 2;
}

// The HeapSizes field is a bitvector that encodes the width of indexes into the various heaps. If bit 0 is
// set, indexes into the “#String” heap are 4 bytes wide; if bit 1 is set, indexes into the “#GUID” heap are
// 4 bytes wide; if bit 2 is set, indexes into the “#Blob” heap are 4 bytes wide. Conversely, if the
// HeapSize bit for a particular heap is not set, indexes into that heap are 2 bytes wide
int GetHeapIndexSize(string heapType)
{
    return heapType switch
    {
        "String" => (heapOfSetSizes & 0x01) != 0 ? 4 : 2,
        "GUID" => (heapOfSetSizes & 0x02) != 0 ? 4 : 2,
        "Blob" => (heapOfSetSizes & 0x04) != 0 ? 4 : 2,
        _ => throw new ArgumentException("Invalid heap type")
    };
}

int MoveToNextZero(int index)
{
    while (bytes[index] != 0 && index < bytes.Length)
    {
        index++;
    }

    return index;
}

int RvaToFileOffset(uint rva)
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

void Advance(int i = 1) => cursor += i;

byte[] GetNext(int len = 1)
{
    var bts = bytes.Skip(cursor).Take(len).ToArray();
    cursor += len;
    return bts;
}

record SectionHeader(string Name, uint VirtualAddress, uint PointerToRawData);

record StreamHeader(uint Size, string Name, int FileOffset);

record Stream(byte HeapOfSetSizes, int MaskValid);

record MethodDef(uint Rva);