package net.tmcf.snmp;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.Timer;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.RollingFileAppender;
import org.snmp4j.smi.OID;

public class SimpleSnmpManager {
	
	private static final Logger LOG = Logger.getLogger(SimpleSnmpManager.class);
	
	private static List<OID> oids = new ArrayList<OID>();
	
	private static Properties kafkaProps = new Properties();
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		configureLogger();

		checkArgs();
		
		setKafkaProps();
		
		long pollingFreqMs = Long.parseLong(System.getProperty("polling.freq"));
		
		Timer timer = new Timer();
		SnmpWalkerTask snmpwalk = new SnmpWalkerTask();
		timer.schedule(snmpwalk, 0, pollingFreqMs);
		
	}
	
	private static void configureLogger() {
		
		BasicConfigurator.configure();
		
		RollingFileAppender fa = new RollingFileAppender();
        fa.setName("FileLogger");
        fa.setFile("log" + File.separator + "clip-snmp-manager.log");
        fa.setLayout(new PatternLayout("%d %-5p [%c{1}] %m%n"));
        fa.setThreshold(Level.DEBUG);
        fa.setAppend(true);
        fa.setMaxBackupIndex(3);
        fa.setMaxFileSize("5MB");
        fa.activateOptions();

        Logger.getRootLogger().addAppender(fa);
		
	}
	
	private static void checkArgs() {
		
		if (!isValidSnmpVersion()) {
			System.out.println("Provide a valid SNMP version: v1, v2c, or v3.");
			System.exit(1);
		}
		
		if (!isValidOids()) {
			System.out.println("OIDs must be separated by a comma or listed in a .txt file, one OID per line.");
			System.exit(1);
		}
		
		if (!isValidCredentials()) {
			System.out.println("Provide required credentials.");
			System.exit(1);
		}
		
		if (System.getProperty("kafka.bootstrap.servers") == null) {
			System.out.println("The Kafka bootstrap servers list should be in the form host1:port1,host2:port2,....");
			System.out.println("Or provide a file instead (list the servers in one line only).");
			System.exit(1);
		}
		
		if (!isNumeric(System.getProperty("polling.freq"))) {
			System.out.println("Provide a numerical value for the polling frequency.");
			System.exit(1);
		}
		
	}
	
	private static boolean isValidSnmpVersion() {
		
		String str = System.getProperty("snmp.version");
		
		if (str != null) {
			if (str.equals("v1") || str.equals("v2c") || str.equals("v3")) {
				return true;
			}
		} 
		
		return false;
		
	}
	
	private static boolean isValidCredentials() {
		
		String version = System.getProperty("snmp.version");
		if (version.equals("v1") || version.equals("v2c")) {			
			if (System.getProperty("community") == null) {
				System.out.println("Community string is required for SNMP v1 and v2c.");
				return false;
			}
			
		} else { // v3
			
			String securityLevel = System.getProperty("security.level");
			if (System.getProperty("security.level") == null || 
					(!securityLevel.equals("noAuthNoPriv") && !securityLevel.equals("authNoPriv") && !securityLevel.equals("authPriv"))) {
				System.out.println("Security level must be one of: noAuthNoPriv, authNoPriv, or authPriv.");
				return false;
			}
			
			if (securityLevel.equals("authNoPriv") || securityLevel.equals("authPriv")) {				
				String authProtocol = System.getProperty("auth.protocol");
				if (!authProtocol.equals("MD5") && !authProtocol.equals("SHA")) {
					System.out.println("Auth protocol must be MD5 or SHA.");
					return false;
				}

				
				if (securityLevel.equals("authPriv")) {	
					String privProtocol = System.getProperty("priv.protocol");
					if (!privProtocol.equals("AES") && !privProtocol.equals("DES")) {
						System.out.println("Priv protocol must be AES or DES.");
						return false;
					}

				}
						
			}
			
		}
		
		return true;
		
	}
	
	private static boolean isValidOids() {
		
		String oidProp = System.getProperty("oid");	
		if (oidProp == null) {
			return false;
		}
		
		try {
			
			if (isValidFile(oidProp)) {				
				File file = new File(oidProp);
				BufferedReader br = new BufferedReader(new FileReader(file));
				 
				String line = null;
				while ((line = br.readLine()) != null) {
					oids.add(new OID(line));
				}
			 
				br.close();
				
				LOG.debug(Arrays.toString(oids.toArray()));				
			} else {				
				String[] oidsStr = (oidProp).split(",");
				for (String oid : oidsStr) {
					oids.add(new OID(oid));
				}
				
				LOG.debug(Arrays.toString(oids.toArray()));				
			}
			
		} catch (RuntimeException ex) {
			System.out.println("One or more invalid OID." + ex.getMessage());
			return false;
		} catch (IOException e) {
			System.out.println("Exception while attempting to read the OID .txt file..." + e.getMessage());
			System.exit(1);
		}
		
		return true;
		
	}

	private static boolean isNumeric(String str) {
		
		if (str == null) {
			return false;
		}
		
		try {
			Long.parseLong(str);
		} catch (NumberFormatException nfe) {
			return false;
		}
		
		return true;
		
	}
	
	private static boolean isValidFile(String path) {
		File file = new File(path);
		if (file.exists()) {
			String ext = path.substring(path.lastIndexOf("."));
			if (ext.equalsIgnoreCase(".txt")) {
				return true;
			}
		}
		return false;
	}
		
	private static void setKafkaProps() {
		
		LOG.debug("Setting Kafka properties... ");
		
		String arg = System.getProperty("kafka.bootstrap.servers");
		String bootstrapServers = arg;	
		
		if (isValidFile(arg)) {	// if a .txt file is provided
			
			File file = new File(arg);
			BufferedReader br;
			
			try {
				
				br = new BufferedReader(new FileReader(file));
				bootstrapServers = br.readLine();
				br.close();

			} catch (Exception e) {
				System.out.println("Exception while reading the Kafka bootstrap servers list file..." + e.getMessage());
				System.exit(1);
			}
			
		}
		
		LOG.debug("Kafka bootstrap servers: " + bootstrapServers);
		kafkaProps.put("bootstrap.servers", bootstrapServers);
		kafkaProps.put("acks", "all");
		kafkaProps.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
		kafkaProps.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");

	}
	
	public static Properties getKafkaProps() {
		return kafkaProps;
	}
	
	public static List<OID> getOidList() {
		return oids;
	}

}