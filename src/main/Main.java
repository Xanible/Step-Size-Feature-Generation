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
 *  This program will produce a weka data file of pairs from dalvik opcodes at a given step size.
 */

public class Main {

	public static void main(String[] args) throws IOException {

		int maxStepSize = 10;

		for(int stepSize = 1; stepSize <= maxStepSize; stepSize++) {
			//Setup
<<<<<<< HEAD
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
=======
			File malDir = new File("D:/Disassembly/Cleaned/Malware/2");
			File benDir = new File("D:/Disassembly/Cleaned/Benign/2");

			//Read in list of pairs
			BufferedReader br = new BufferedReader(new FileReader("D:/Pair-Lists/Pair"  + stepSize + ".txt"));
>>>>>>> parent of 9e9521a... Initial Commit
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
<<<<<<< HEAD
			//Prepare the data file
			BufferedWriter output = new BufferedWriter(new FileWriter("C:/Users/colby/Desktop/stuff/Step" + stepSize + "/Pair_Step_" + stepSize + ".txt"));
			//BufferedWriter output = new BufferedWriter(new FileWriter("C:/Users/colby/Desktop/SCHOOL/AndroidCT/Step Size Classifiers/Data Files/Pair_Step_" + stepSize + ".arff"));
			
=======
			//Prepare the arff file
			BufferedWriter arff = new BufferedWriter(new FileWriter("C:/Users/colbyadmin/Desktop/SCHOOL/AndroidCT/Train 1/Pair_Step_" + stepSize + ".arff"));
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
>>>>>>> parent of 9e9521a... Initial Commit

			//Read in List of files to test
			//BufferedReader br2 = new BufferedReader(new FileReader("C:\\Users\\colby\\Desktop\\SCHOOL\\AndroidCT\\File Lists\\Train 1.txt"));
			List<String> malFileList = new ArrayList<String>();
			List<String> benFileList = new ArrayList<String>();
			File[] fl1 = malDir.listFiles();
			File[] fl2 = benDir.listFiles();
			
			for(int i = 0; i < fl1.length; i++) {
				malFileList.add(fl1[i].getName());
			}
			for(int i = 0; i < fl2.length; i++) {
				benFileList.add(fl2[i].getName());
			}
			
<<<<<<< HEAD
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
=======
			/*
>>>>>>> parent of 9e9521a... Initial Commit
			br2.readLine();
			int incrementer = 1;
			for (String line = br2.readLine(); line != null; line = br2.readLine()) {
				if(incrementer < 501) {
					malFileList.add(line);
					incrementer++;
				} else if(incrementer == 501) {
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
<<<<<<< HEAD
			br2.close();

			incrementer = 1;
=======
			br2.close();	


>>>>>>> parent of f1215cd... okay
=======
			br2.close();*/

			int incrementer = 1;
>>>>>>> parent of 9e9521a... Initial Commit
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
									currentVal = 1;
									sequencesCount.put(p, currentVal);
								} else {
<<<<<<< HEAD
									System.out.println(p);
<<<<<<< HEAD
=======
									System.out.println(s);
>>>>>>> parent of f1215cd... okay
									System.exit(0);
=======
									//System.exit(0);
>>>>>>> parent of 9e9521a... Initial Commit
								}
							}

						}
					}

					//Print out sequence frequency file
					arff.write("Malware");
					for(String op: opcodePairList){
						arff.write("," + Integer.toString(sequencesCount.get(op)));
					}
					arff.newLine();
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
									currentVal = 1;
									sequencesCount.put(p, currentVal);
								} else {
<<<<<<< HEAD
									System.out.println(p);
<<<<<<< HEAD
=======
									System.out.println(s);
>>>>>>> parent of f1215cd... okay
									System.exit(0);
=======
									//System.exit(0);
>>>>>>> parent of 9e9521a... Initial Commit
								}
							}

						}
					}

					//Print out sequence frequency file
					arff.write("Benign");
					for(String op: opcodePairList){
						arff.write("," + Integer.toString(sequencesCount.get(op)));
					}
					arff.newLine();
					incrementer++;

				} catch (Exception e) {
					System.out.println("Error reading from benign file!");
				}
			}
			arff.close();
		}
	}


}
