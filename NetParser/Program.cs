using var fs = new FileStream("../HelloWorld.dll", FileMode.Open, FileAccess.Read);

Console.WriteLine(fs.Length);