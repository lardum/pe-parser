using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

var bytes = File.ReadAllBytes("../HelloWorld.dll");
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

Console.WriteLine(JsonSerializer.Serialize(sectionHeaders));

return;

uint RvaToFileOffset(uint rva)
{
    foreach (var (_, virtualAddress, pointerToRawData) in sectionHeaders)
    {
        if (rva >= virtualAddress && rva < virtualAddress + virtualAddress)
        {
            return (uint)(pointerToRawData + (rva - virtualAddress));
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