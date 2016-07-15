using System.Collections.Generic;
using Jose;
using NUnit.Framework;

namespace UnitTests
{
    [TestFixture]
    public class DictionariesTest
    {
        [Test]
        public void Append()
        {
            //given
            var src = new Dictionary<string, string> {{"one", "1"}, {"two", "2"}};
            var other = new Dictionary<string, string> {{"three", "3"}, {"two", "3"}};
            
            //when
            Dictionaries.Append(src, other);

            //then
            Assert.That(src, Has.Count.EqualTo(3));
            Assert.That(src["one"],Is.EqualTo("1"));
            Assert.That(src["two"],Is.EqualTo("2"));
            Assert.That(src["three"],Is.EqualTo("3"));
        }

        [Test]
        public void AppendNull()
        {
            //given
            var src = new Dictionary<string, string> { { "one", "1" }, { "two", "2" } };

            //when
            Dictionaries.Append(src, null);

            //then
            Assert.That(src, Has.Count.EqualTo(2));
            Assert.That(src["one"], Is.EqualTo("1"));
            Assert.That(src["two"], Is.EqualTo("2"));
        }
    }
}