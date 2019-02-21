package main;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* 
 *  This program will produce a libsvm data file of pairs from dalvik opcodes at a given step size.
 */

public class Main {

	public static void main(String[] args) throws IOException {

		int maxStepSize = 10;

		for(int stepSize = 2; stepSize <= maxStepSize; stepSize++) {
			//Setup
<<<<<<< HEAD
			File malDir = new File("G:\\My Drive\\Android-Classification\\Blah\\cleaned\\malware");
			File benDir = new File("G:\\My Drive\\Android-Classification\\Blah\\cleaned\\benign");

			//Read in list of pairs
			BufferedReader br = new BufferedReader(new FileReader("G:\\My Drive\\Android-Classification\\Blah\\Pair-Lists\\Pair"  + stepSize + ".txt"));
=======
			File malDir = new File("C:\\Users\\colby\\Desktop\\SCHOOL\\AndroidCT\\Cleaned Disassembly\\Malware");
			File benDir = new File("C:\\Users\\colby\\Desktop\\SCHOOL\\AndroidCT\\Cleaned Disassembly\\Benign");

			//Read in list of pairs
			BufferedReader br = new BufferedReader(new FileReader("C:\\Users\\colby\\Desktop\\SCHOOL\\AndroidCT\\Pairing Lists\\Pair"  + stepSize + ".txt"));
>>>>>>> parent of f1215cd... okay
			List<String> opcodePairList = new ArrayList<String>();
			for (String line = br.readLine(); line != null; line = br.readLine()) {
				opcodePairList.add(line);
			}
			br.close();	

			//Create master hashmaps
			HashMap<String, Integer> sequencesMasterList = new HashMap<String, Integer>();
			for(String s: opcodePairList){
				sequencesMasterList.put(s, 0);
			}

<<<<<<< HEAD
			//Prepare the data file
			BufferedWriter output = new BufferedWriter(new FileWriter("C:/Users/colby/Desktop/stuff/Step" + stepSize + "/Pair_Step_" + stepSize + ".txt"));
			//BufferedWriter output = new BufferedWriter(new FileWriter("C:/Users/colby/Desktop/SCHOOL/AndroidCT/Step Size Classifiers/Data Files/Pair_Step_" + stepSize + ".arff"));
			

			//Read in List of files to test
			BufferedReader br2 = new BufferedReader(new FileReader("C:\\Users\\colby\\Desktop\\Stuff\\List of Files.txt"));
			//BufferedReader br2 = new BufferedReader(new FileReader("C:\\Users\\colby\\Desktop\\SCHOOL\\AndroidCT\\Test Files.txt"));
			List<String> malFileList = new ArrayList<String>();
			List<String> benFileList = new ArrayList<String>();
			File[] fl1 = malDir.listFiles();
			File[] fl2 = benDir.listFiles();
			
			/*
			for(int i = 0; i < fl1.length; i++) {
				malFileList.add(fl1[i].getName());
			}
			for(int i = 0; i < fl2.length; i++) {
				benFileList.add(fl2[i].getName());
			}*/
			
			
=======
			//Prepare the arff file
			BufferedWriter arff = new BufferedWriter(new FileWriter("C:/Users/colby/Desktop/SCHOOL/AndroidCT/Step Size Classifiers/Data Files/Train 1/Pair_Step_" + stepSize + ".arff"));
			//BufferedWriter arff = new BufferedWriter(new FileWriter("C:/Users/colby/Desktop/SCHOOL/AndroidCT/Step Size Classifiers/Data Files/Train 2/Pair_Step_" + stepSize + ".arff"));
			arff.write("@relation Benign-Malware");
			arff.newLine();
			arff.newLine();
			arff.write("@attribute @@class@@ {Benign,Malware}");
			arff.newLine();
			for(String s: opcodePairList){
				arff.write("@attribute \"" + s + "\" numeric");
				arff.newLine();
			}
			arff.newLine();
			arff.write("@data");
			arff.newLine();

			//Read in List of files to test
			BufferedReader br2 = new BufferedReader(new FileReader("C:\\Users\\colby\\Desktop\\SCHOOL\\AndroidCT\\File Lists\\Train 1.txt"));
			List<String> malFileList = new ArrayList<String>();
			List<String> benFileList = new ArrayList<String>();
>>>>>>> parent of f1215cd... okay
			br2.readLine();
			int incrementer = 1;
			for (String line = br2.readLine(); line != null; line = br2.readLine()) {
				if(incrementer < 1001) {
					malFileList.add(line);
					incrementer++;
				} else if(incrementer == 1001) {
					System.out.println(line);
					br2.readLine();
					benFileList.add(br2.readLine());
					incrementer++;
				} else {
					benFileList.add(line);
					incrementer++;
				}
			}
<<<<<<< HEAD
			br2.close();

			incrementer = 1;
=======
			br2.close();	


>>>>>>> parent of f1215cd... okay
			//Sequencing loops
			incrementer = 1;
			for(String s: malFileList) {
				System.out.println(incrementer);
				try {
					//Output file name
					System.out.println(s);

					//Read in a file
					String filePath = malDir.getPath() + "\\" +s;
					File f = new File(filePath);

					List<String> theFile = Files.readAllLines(f.toPath(), Charset.defaultCharset() );
					String[] words = theFile.get(0).split(" ");
					List<String> opcodes = new ArrayList<String>(Arrays.asList(words));

					//Send file through sequencer
					HashMap<String, Integer> sequencesCount = new HashMap<String,Integer>(sequencesMasterList);
					for(int i = 0;i < opcodes.size() - stepSize;i++) {
						if(!opcodes.get(i).equals(".end-method")) {
							List<String> l = new ArrayList<String>();
							for(int j = 1; j < stepSize; j++) {
								l.add(opcodes.get(i + j));
							}
							if(!l.contains(".end-method")) {
								String p = opcodes.get(i) + " " + opcodes.get(i + stepSize);
								if(sequencesCount.containsKey(p)) {
									int currentVal = sequencesCount.get(p);
									// Binary
									//currentVal = 1;
									
									// Count
									currentVal++;
									sequencesCount.put(p, currentVal);
								} else {
<<<<<<< HEAD
									System.out.println(p);
=======
									System.out.println(s);
>>>>>>> parent of f1215cd... okay
									System.exit(0);
								}
							}

						}
					}

					//Print out sequence frequency file
					output.write("1");
					int index = 1;
					for(String op: opcodePairList){
						output.write(" " + Integer.toString(index) + ":" + Integer.toString(sequencesCount.get(op)));
						index++;
					}
					output.newLine();
					incrementer++;

				} catch (Exception e) {
					System.out.println("Error reading from malware file!");
				}
			}

			incrementer = 1;
			for(String s: benFileList) {
				System.out.println(incrementer);
				try {
					//Output file name
					System.out.println(s);

					//Read in a file
					String filePath = benDir.getPath() + "\\" +s;
					File f = new File(filePath);

					List<String> theFile = Files.readAllLines(f.toPath(), Charset.defaultCharset() );
					String[] words = theFile.get(0).split(" ");
					List<String> opcodes = new ArrayList<String>(Arrays.asList(words));

					//Send file through sequencer
					HashMap<String, Integer> sequencesCount = new HashMap<String,Integer>(sequencesMasterList);
					for(int i = 0;i < opcodes.size() - stepSize;i++) {
						if(!opcodes.get(i).equals(".end-method")) {
							List<String> l = new ArrayList<String>();
							for(int j = 1; j < stepSize; j++) {
								l.add(opcodes.get(i + j));
							}
							if(!l.contains(".end-method")) {
								String p = opcodes.get(i) + " " + opcodes.get(i + stepSize);
								if(sequencesCount.containsKey(p)) {
									int currentVal = sequencesCount.get(p);
									// Binary
									//currentVal = 1;
									
									// Count
									currentVal++;
									sequencesCount.put(p, currentVal);
								} else {
<<<<<<< HEAD
									System.out.println(p);
=======
									System.out.println(s);
>>>>>>> parent of f1215cd... okay
									System.exit(0);
								}
							}

						}
					}

					//Print out sequence frequency file
					output.write("0");
					int index = 1;
					for(String op: opcodePairList){
						output.write(" " + Integer.toString(index) + ":" + Integer.toString(sequencesCount.get(op)));
						index++;
					}
					output.newLine();
					incrementer++;

				} catch (Exception e) {
					System.out.println("Error reading from benign file!");
				}
			}
			output.close();
		}
	}


}
