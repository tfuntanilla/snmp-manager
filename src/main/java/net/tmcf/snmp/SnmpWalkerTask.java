package net.tmcf.snmp;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TimerTask;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.log4j.Logger;
import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.util.DefaultPDUFactory;
import org.snmp4j.util.TreeEvent;
import org.snmp4j.util.TreeUtils;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Simple snmpwalker program.
 * 
 * @author tfuntani
 *
 */
public class SnmpWalkerTask extends TimerTask {

	private static final Logger LOG = Logger.getLogger(SnmpWalkerTask.class);
	private SimpleSnmpWalker snmpwalker = SimpleSnmpWalker.getInstance();
	private static List<OID> oids = SimpleSnmpManager.getOidList();
	private static final String kafkaTopic = System.getProperty("kafka.topic");

	private static int i = 0;

	@Override
	public void run() {

		LOG.debug("Starting snmpwalk. Count: " + (++i));

		try {
			
			snmpwalker.getSnmp().listen();

			if (snmpwalker.getTarget().getVersion() == SnmpConstants.version3) {
				snmpWalkV3();
			} else {
				snmpWalkV1V2();
			}

		} catch (IOException e) {
			LOG.debug("Exception while running snmpwalk.", e);
		}

	}
	
	private void snmpWalkV1V2() {
		
		try {
			
			for (OID oid : oids) {
				
				Map<String, String> results = new HashMap<String, String>();
				LOG.debug("Snmpwalk on " + snmpwalker.getTarget().getAddress() + ", OID: " + oid.toDottedString());
			
				TreeUtils treeUtils = new TreeUtils(snmpwalker.getSnmp(), new DefaultPDUFactory());
				List<TreeEvent> events = treeUtils.getSubtree(snmpwalker.getTarget(), oid);
				if (events == null || events.size() == 0) {
					LOG.debug("No result returned for " + oid + ". Events list is null or empty.");
				}
	
				for (TreeEvent event : events) {
					if (event != null) {
						if (event.isError()) {
							LOG.error("OID [" + oid + "] " + event.getErrorMessage());
						}
						VariableBinding[] varBindings = event.getVariableBindings();
						if (varBindings == null || varBindings.length == 0) {
							LOG.debug("No result returned for " + oid + ". Variable bindings array is null or empty.");
						} else {
							for (VariableBinding varBinding : varBindings) {
								String key = varBinding.toString().substring(0, varBinding.toString().indexOf("=") - 1);
								String value = varBinding.getVariable().toString();
								LOG.debug(key + " = " + value);
								results.put(key, value);
							}
						}
					}
				}
				
				// forward results to Kafka
				forwardResults(oid.toDottedString(), results);
			}
			
			snmpwalker.getSnmp().close();
			LOG.debug("Snmpwalk done.");
			
		} catch (Exception e) {
			LOG.error("Error while executing snmpwalk task.", e);
		}
			
	}

	private void snmpWalkV3() {

		try {

			// snmpwalk on the oids
			for (OID oid : oids) {

				Map<String, String> results = new HashMap<String, String>();
				LOG.debug("Snmpwalk on " + snmpwalker.getTarget().getAddress() + ", OID: " + oid.toDottedString());

				PDU pdu = new ScopedPDU();
				pdu.addOID(new VariableBinding(oid));
				pdu.setType(PDU.GETNEXT);

				String prefix = oid.toDottedString();
				String key = prefix;

				// 1. Start with provided OID, then traverse the tree			
				// 2. Stop when the OID from GETNEXT no longer has the original OID as the prefix or when response is null or when the variable bindings is empty
				ResponseEvent response = snmpwalker.getSnmp().getNext(pdu, snmpwalker.getTarget());
				while (key.startsWith(prefix) && response.getResponse() != null && !response.getResponse().getVariableBindings().isEmpty()) {

					// only get the last variable binding, since the previous ones would be from the previous OIDs
					VariableBinding vb = response.getResponse().getVariableBindings().lastElement();

					// set the OID as the new key
					key = response.getResponse().getVariableBindings().lastElement().getOid().toDottedString();
					String value = vb.getVariable().toString();
					if (key.startsWith(prefix) && value != null && value.length() > 0) {
						LOG.debug(key + " = " + value);
						results.put(key, value);
					}

					// add the OID that resulted from the GETNEXT request to the PDU and repeat
					pdu.addOID(new VariableBinding(new OID(key)));
					response = snmpwalker.getSnmp().getNext(pdu, snmpwalker.getTarget());

				}
				
				LOG.debug("Last OID checked: " + key);
				if (response.getResponse() == null) {
					LOG.debug("OID [" + key + "] response is null");
				}

				// forward results to Kafka
				forwardResults(oid.toDottedString(), results);

			}

			snmpwalker.getSnmp().close();
			LOG.debug("Snmpwalk done.");

		} catch (Exception e) {
			LOG.error("Error while executing snmpwalk task.", e);
		}
	}
	
	private void forwardResults(String oid, Map<String, String> results) {
		
		String resultsJson = resultsToJson(oid, results);

		// forward to kafka
		LOG.debug("Forwarding results to Kafka...");

		Producer<String, String> producer = new KafkaProducer<String, String>(SimpleSnmpManager.getKafkaProps());
		producer.send(new ProducerRecord<String, String>(kafkaTopic, oid, resultsJson));

		producer.close();
		
	}

	private String resultsToJson(String oid, Map<String, String> results) {

		// create json object to be sent to kafka
		JsonParser parser = new JsonParser();

		JsonObject json = new JsonObject();
		json.addProperty("oid", oid);
		json.addProperty("targetHost", snmpwalker.getTarget().getAddress().toString());
		json.addProperty("snmpVersion", snmpwalker.getTarget().getVersion());
		json.addProperty("contextName", (System.getProperty("context.name") == null) ? "" : System.getProperty("context.name"));
		json.addProperty("contextEngineId", new OctetString(snmpwalker.getLocalEngineID()).toString());

		JsonObject subtree = new JsonObject();
		for (Map.Entry<String, String> entry : results.entrySet()) {
			subtree.addProperty(entry.getKey(), entry.getValue());
		}

		JsonElement subtreeElement = parser.parse(subtree.toString());
		json.add("results", subtreeElement);

		return json.toString();

	}

}
