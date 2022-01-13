diff --git a/src/connection.rs b/src/connection.rs
index 19a5ab2..ef88bb9 100644
--- a/src/connection.rs
+++ b/src/connection.rs
@@ -483,8 +483,7 @@ impl Connection {
             .encrypt_bytes(packet.get_payload(), self.is_client().unwrap());
 
         // encrypt payload
-        packet.set_encrypted_payload(Some(enc_payload));
-        packet.push_encryption_to_payload();
+        packet.set_payload(enc_payload);
 
         if signature.len() > 0 {
             packet.set_signature_header(SignatureHeader::new(signature));
diff --git a/src/connection_security.rs b/src/connection_security.rs
index 9e24d90..dc7d9dd 100644
--- a/src/connection_security.rs
+++ b/src/connection_security.rs
@@ -23,7 +23,7 @@ use sha3::Sha3_256;
 use std::path::Path;
 use std::sync::{Arc, Mutex, MutexGuard};
 use std::thread;
-use std::time::Duration;
+use std::time::{Duration, SystemTime, UNIX_EPOCH};
 use std::{fs, io};
 
 #[derive(Debug)]
@@ -44,6 +44,8 @@ pub struct Security {
     key_initial_vector: Option<BigInt>,
     aes_key_stream_encrypt: Option<Aes256Ctr>,
     aes_key_stream_decrypt: Option<Aes256Ctr>,
+    timestamp: u128,
+    lifetime: Duration,
 }
 
 lazy_static! {
@@ -90,9 +92,23 @@ impl Security {
             key_initial_vector: None,
             aes_key_stream_encrypt: None,
             aes_key_stream_decrypt: None,
+            timestamp: SystemTime::now()
+                .duration_since(UNIX_EPOCH)
+                .unwrap()
+                .as_millis()
+                + 1_000_000_000, // with this initial value key_valid allways retruns true
+            lifetime: Duration::from_secs(60 * 1000),
         }
     }
 
+    pub fn key_valid(&self) -> bool {
+        self.timestamp + self.lifetime.as_millis()
+            > SystemTime::now()
+                .duration_since(UNIX_EPOCH)
+                .unwrap()
+                .as_millis()
+    }
+
     pub fn check_certificate(&mut self, payload: Vec<u8>) -> Result<(), &'static str> {
         self.other_recieved_certificate_bytes
             .extend_from_slice(&payload);
@@ -283,6 +299,12 @@ impl Security {
                 .modpow(&self.dh_private_key.as_ref().unwrap(), &prime),
         );
 
+        // set key timestamp to current time
+        self.timestamp = SystemTime::now()
+            .duration_since(UNIX_EPOCH)
+            .unwrap()
+            .as_millis();
+
         self.derive_keys();
     }
 
@@ -318,6 +340,12 @@ impl Security {
                 .modpow(&self.dh_private_key.as_ref().unwrap(), &prime),
         );
 
+        // set key timestamp to current time
+        self.timestamp = SystemTime::now()
+            .duration_since(UNIX_EPOCH)
+            .unwrap()
+            .as_millis();
+
         self.derive_keys();
 
         let mut payload = Vec::new();
diff --git a/src/packet.rs b/src/packet.rs
index 555a1a7..1cd6ea2 100644
--- a/src/packet.rs
+++ b/src/packet.rs
@@ -315,17 +315,6 @@ impl Packet {
         self.payload = payload;
     }
 
-    pub fn set_encrypted_payload(&mut self, payload: Option<Vec<u8>>) {
-        self.encrypted_payload = payload;
-    }
-
-    pub fn push_encryption_to_payload(&mut self) {
-        match &self.encrypted_payload {
-            None => {}
-            Some(payload) => self.payload = payload.to_vec(),
-        }
-    }
-
     pub fn from_bytes(bytes: &[u8]) -> Result<Self, &str> {
         if bytes.len() < 16 {
             return Err("Packet length is invalid");
