using Xunit;
using Xunit.Abstractions;

namespace UnitTests
{
    public class JwkTest
    {
        private TestConsole Console;

        public JwkTest(ITestOutputHelper output)
        {
            Console = new TestConsole(output);
        }

        [Fact]
        public void ToJson_OctKey()
        {
            //given
            //var key = new JWK();

            //when

            //then
        }


    }
}
