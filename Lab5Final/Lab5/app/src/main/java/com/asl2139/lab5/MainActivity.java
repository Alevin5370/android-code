package com.asl2139.lab5;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKeys;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class MainActivity extends AppCompatActivity {
    private static final String KEY_ALIAS = "MySecureKey";
    private static final String FILE_NAME = "data.txt";
    private EditText editText;
    private Button saveButton;
    private Button AccessCE;
    private Button AccessDE;
    private Button AccessExternal;
    private SharedPreferences securePrefs;
    private SharedPreferences deviceEncryptedPrefs;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        editText = findViewById(R.id.edtData);
        saveButton = findViewById(R.id.btnEncryptFile);
        AccessCE = findViewById(R.id.AccessCE);
        AccessDE = findViewById(R.id.AccessDE);
        AccessExternal = findViewById(R.id.AccessExternal);

        try {
            securePrefs = getSecurePreferences();
        } catch (GeneralSecurityException | IOException e) {
            Log.e("SecureStorage", "Error initializing EncryptedSharedPreferences", e);
            Toast.makeText(this, "Security Error!", Toast.LENGTH_SHORT).show();
            return;
        }

        // Load saved data
        String savedText = securePrefs.getString("secureData", "");
        editText.setText(savedText);

        Context deviceProtectedContext = getApplicationContext().createDeviceProtectedStorageContext();
        deviceEncryptedPrefs = deviceProtectedContext.getSharedPreferences("device_encrypted_prefs", Context.MODE_PRIVATE);

        saveButton.setOnClickListener(view -> {
            String textToSave = editText.getText().toString();
            if (!textToSave.isEmpty()) {
                deviceEncryptedPrefs.edit().putString("secure_text", textToSave).apply();
                saveSecureData(textToSave);
                String encryptedData = null;
                try {
                    encryptedData = encryptData(textToSave);
                } catch (Exception e) {
                    Toast.makeText(MainActivity.this, "failed to encrypt", Toast.LENGTH_SHORT).show();
                }
                if (encryptedData != null) {
                    saveToFile(encryptedData);
                    ///Toast.makeText(MainActivity.this, "encrypted Data securely", Toast.LENGTH_SHORT).show();
                }
                Toast.makeText(MainActivity.this, "Data saved securely", Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(MainActivity.this, "Enter some text first!", Toast.LENGTH_SHORT).show();
            }
        });
        AccessCE.setOnClickListener(view -> {
            String ceData = securePrefs.getString("secureData", "No CE Data Found");
            Toast.makeText(MainActivity.this, "CE Data: " + ceData, Toast.LENGTH_LONG).show();
        });
        AccessDE.setOnClickListener(view -> {
            String deData = deviceEncryptedPrefs.getString("secure_text", "No DE Data Found");
            Toast.makeText(MainActivity.this, "DE Data: " + deData, Toast.LENGTH_LONG).show();
        });
        AccessExternal.setOnClickListener(view -> {
            String externalData = readFromFile();
            String decrypted = "";
            try {
                decrypted = decryptData(externalData);
            } catch (Exception e) {
                Toast.makeText(MainActivity.this, "Couldn't decrypt", Toast.LENGTH_LONG).show();
            }
            Toast.makeText(MainActivity.this, "External Data: " + decrypted, Toast.LENGTH_LONG).show();
        });
    }
    private SharedPreferences getSecurePreferences() throws GeneralSecurityException, IOException {
        Context credentialStorageContext = createDeviceProtectedStorageContext();
        credentialStorageContext.moveSharedPreferencesFrom(this, "secure_prefs");

        String masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC);
        return EncryptedSharedPreferences.create(
                "secure_prefs",
                masterKeyAlias,
                credentialStorageContext,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );
    }
    private void saveSecureData(String data) {
        SharedPreferences.Editor editor = securePrefs.edit();
        editor.putString("secureData", data);
        editor.apply();
        ///Toast.makeText(this, "Data Saved Securely!", Toast.LENGTH_SHORT).show();
    }
    private void generateSecretKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        if (!keyStore.containsAlias(KEY_ALIAS)) {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            keyGenerator.init(
                    new KeyGenParameterSpec.Builder(KEY_ALIAS,
                            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .setKeySize(256)
                            .build()
            );
            keyGenerator.generateKey();
        }
    }
    private SecretKey getSecretKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (!keyStore.containsAlias(KEY_ALIAS)) {  // Check if key already exists
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

            KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build();

            keyGenerator.init(keyGenParameterSpec);
            keyGenerator.generateKey();
        }
        return ((KeyStore.SecretKeyEntry) keyStore.getEntry(KEY_ALIAS, null)).getSecretKey();
    }

    private String encryptData(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey secretKey = getSecretKey();

        // Let the system generate the IV automatically
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] iv = cipher.getIV(); // Retrieve the auto-generated IV
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Combine IV and ciphertext
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(iv);
        outputStream.write(ciphertext);

        return Base64.encodeToString(outputStream.toByteArray(), Base64.DEFAULT);
    }
    private String decryptData(String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey secretKey = getSecretKey();

        byte[] combined = Base64.decode(encryptedData, Base64.DEFAULT);

        // Extract IV and ciphertext
        byte[] iv = new byte[12]; // IV size for AES-GCM
        byte[] ciphertext = new byte[combined.length - 12];

        System.arraycopy(combined, 0, iv, 0, 12);
        System.arraycopy(combined, 12, ciphertext, 0, ciphertext.length);

        // Use the extracted IV for decryption
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));

        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }
    private void saveToFile(String data) {
        File externalFile = new File(getExternalFilesDir(null), FILE_NAME);
        try (FileOutputStream fos = new FileOutputStream(externalFile)) {
            fos.write(data.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    private String readFromFile() {
        File externalFile = new File(getExternalFilesDir(null), FILE_NAME);
        StringBuilder sb = new StringBuilder();
        try (FileInputStream fis = new FileInputStream(externalFile);
             InputStreamReader isr = new InputStreamReader(fis);
             BufferedReader reader = new BufferedReader(isr)) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return sb.toString();
    }
}
