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

Console.WriteLine(cursor);

return;

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