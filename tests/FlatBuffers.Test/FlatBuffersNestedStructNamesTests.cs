using NestedStructNames;

namespace Google.FlatBuffers.Test
{
    [FlatBuffersTestClass]
    public class FlatBuffersNestedStructNamesTests
    {
        [FlatBuffersTestMethod]
        public void PreserveCaseNestedStructRoundTrip()
        {
            var value = new RootT
            {
                PAIR_VALUE = new PairT
                {
                    TERMINAL_A = new IndexT { HAS_VALUE = true, VALUE_0 = 17 }
                },
                PAIR_ARRAY = new PairArrayT
                {
                    TERMINAL_LIST = new[]
                    {
                        new IndexT { HAS_VALUE = false, VALUE_0 = 23 },
                        new IndexT { HAS_VALUE = true, VALUE_0 = 31 }
                    }
                },
                PAIRS = new System.Collections.Generic.List<PairT>
                {
                    new PairT
                    {
                        TERMINAL_A = new IndexT { HAS_VALUE = true, VALUE_0 = 47 }
                    }
                }
            };
            var builder = new FlatBufferBuilder(128);
            Root.FinishRootBuffer(builder, Root.Pack(builder, value));
            var unpacked = Root.GetRootAsRoot(builder.DataBuffer).UnPack();
            Assert.AreEqual(true, unpacked.PAIR_VALUE.TERMINAL_A.HAS_VALUE);
            Assert.AreEqual(17, unpacked.PAIR_VALUE.TERMINAL_A.VALUE_0);
            Assert.AreEqual(2, unpacked.PAIR_ARRAY.TERMINAL_LIST.Length);
            Assert.AreEqual(false, unpacked.PAIR_ARRAY.TERMINAL_LIST[0].HAS_VALUE);
            Assert.AreEqual(23, unpacked.PAIR_ARRAY.TERMINAL_LIST[0].VALUE_0);
            Assert.AreEqual(true, unpacked.PAIR_ARRAY.TERMINAL_LIST[1].HAS_VALUE);
            Assert.AreEqual(31, unpacked.PAIR_ARRAY.TERMINAL_LIST[1].VALUE_0);
            Assert.AreEqual(1, unpacked.PAIRS.Count);
            Assert.AreEqual(true, unpacked.PAIRS[0].TERMINAL_A.HAS_VALUE);
            Assert.AreEqual(47, unpacked.PAIRS[0].TERMINAL_A.VALUE_0);
        }
    }
}
