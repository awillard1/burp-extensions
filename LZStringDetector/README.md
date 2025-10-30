#### Download the files
#### Ensure you have a jdk (download and install if not)
https://www.oracle.com/java/technologies/downloads
#### Compile
###### Windows
```
#cd to where the files are located
javac -cp "C:\Users\<YOUR_USERNAME>\AppData\Local\BurpSuitePro\burpsuite_pro.jar" LZStringDetector.java BurpExtender.java --release 21
"c:\Program Files\Java\jdk-25\bin\jar.exe" cvf LZStringDetector.jar *
```
###### Linux
```
#cd to where the files are located
#locate your burpsuite_pro.jar and change the path in the javac command (currently release 21 to 24 should be able to be used to compile the source)
javac -cp "burpsuite_pro.jar" LZStringDetector.java BurpExtender.java --release 21
jar cvf LZStringDetector.jar *
```
###### Load the jar in burp extensions as Java
