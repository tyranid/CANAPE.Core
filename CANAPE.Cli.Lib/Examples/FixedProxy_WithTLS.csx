// PortFormatProxy.csx – Simple TCP port-forwarding proxy
// Expose methods like WriteLine and WritePackets.
using static System.Console;
using static CANAPE.Cli.ConsoleUtils;

// Create proxy template.
var template = new FixedProxyTemplate();
template.LocalPort = 4443;
template.Host = "www.nostarch.com";
template.Port = 443;
var tls = new TlsNetworkLayerFactory();
template.AddLayer(tls);

// Create proxy instance and start.
var service = template.Create();
service.Start();

WriteLine("Created {0}", service);
WriteLine("Press Enter to exit...");
ReadLine();
service.Stop();

// Dump packets.
var packets = service.Packets;
WriteLine("Captured {0} packets:",
    packets.Count);
WritePackets(packets);