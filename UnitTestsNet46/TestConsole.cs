using Xunit.Abstractions;

namespace UnitTests
{
    public class TestConsole
    {
        public TestConsole(ITestOutputHelper output)
        {
            this.Out = output;
        }

        public ITestOutputHelper Out { get; }
    }
}