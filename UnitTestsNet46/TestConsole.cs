using Xunit.Abstractions;

namespace UnitTests
{
    public class TestConsole
    {
        private readonly ITestOutputHelper output;

        public TestConsole(ITestOutputHelper output)
        {
            this.output = output;
        }

        public ITestOutputHelper Out
        {
            get { return output; }
        }
    }
}