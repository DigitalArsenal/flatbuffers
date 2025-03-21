echo "************************ Java:"

bash JavaTest.sh

echo "************************ Kotlin:"

bash KotlinTest.sh

echo "************************ Go:"

bash GoTest.sh

echo "************************ Python:"

bash PythonTest.sh

echo "************************ TypeScript:"

python3 ts/TypeScriptTest.py

echo "************************ C++:"

cd ..
./flattests
cd tests

echo "************************ C#:"

cd FlatBuffers.Test
bash NetTest.sh
cd ..

echo "************************ PHP:"

php phpTest.php
bash phpUnionVectorTest.sh

echo "************************ Dart:"

bash DartTest.sh

echo "************************ Rust:"

bash RustTest.sh

echo "************************ Lobster:"

# TODO: test if available.
# lobster lobstertest.lobster

echo "************************ C:"

echo "(in a different repo)"

echo "************************ Swift:"

cd FlatBuffers.Test.Swift
bash SwiftTest.sh
cd ..
