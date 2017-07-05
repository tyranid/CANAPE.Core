using System;
using System.IO;

namespace CANAPE.Net.Layers
{
    public interface IDataParserLayer
    {
        bool NegotiateProtocol(Stream clientStream, Stream serverStream);
    }
}
