using static System.Console;
using static CANAPE.Cli.ConsoleUtils;
using CANAPE.Utils;

var template = new NetClientTemplate();
template.Port = 12345;
template.Host = "127.0.0.1";

using(var adapter = template.Connect()) {
  var reader = new DataReader(adapter);
  var writer = new DataWriter(adapter);
  while(!reader.Eof) {
      writer.WriteLine("Hello");
      string line = reader.ReadLine();
      if (line.Length == 0)
        break;
      WriteLine(line.TrimEnd());
  }
}
WriteLine("Done");
