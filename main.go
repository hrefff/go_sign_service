package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
)

func main() {
	// Определяем флаги командной строки
	genKeys := flag.Bool("gen-keys", false, "Generate RSA keys")
	signFile := flag.String("sign", "", "Sign a file")
	verifyFile := flag.String("verify", "", "Verify a file")
	publicKeyFile := flag.String("pub", "public.pem", "Public key file")
	privateKeyFile := flag.String("priv", "private.pem", "Private key file")
	signatureFile := flag.String("sig", "signature.sig", "Signature file")

	flag.Parse()

	switch {
	case *genKeys:
		err := generateKeys(*publicKeyFile, *privateKeyFile)
		if err != nil {
			fmt.Println("Error generating keys:", err)
			os.Exit(1)
		}
		fmt.Println("Keys generated successfully")
	case *signFile != "":
		err := signTextFile(*signFile, *privateKeyFile, *signatureFile)
		if err != nil {
			fmt.Println("Error signing file:", err)
			os.Exit(1)
		}
		fmt.Println("File signed successfully")
	case *verifyFile != "":
		err := verifyTextFile(*verifyFile, *publicKeyFile, *signatureFile)
		if err != nil {
			fmt.Println("Verification failed:", err)
			os.Exit(1)
		}
		fmt.Println("Verification successful")
	default:
		fmt.Println("No valid action specified")
		flag.Usage()
	}
}

func generateKeys(publicKeyFile, privateKeyFile string) error {
	// Генерация ключей
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Сохранение приватного ключа
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	err = os.WriteFile(privateKeyFile, privateKeyPEM, 0600)
	if err != nil {
		return err
	}

	// Сохранение публичного ключа
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	err = os.WriteFile(publicKeyFile, publicKeyPEM, 0644)
	if err != nil {
		return err
	}

	return nil
}

func signTextFile(filename, privateKeyFile, signatureFile string) error {
	// Чтение файла
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	// Чтение приватного ключа
	privateKeyData, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(privateKeyData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	// Создание хэша
	hashed := sha256.Sum256(data)

	// Подпись хэша
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return err
	}

	// Сохранение подписи
	err = os.WriteFile(signatureFile, signature, 0644)
	if err != nil {
		return err
	}

	return nil
}

func verifyTextFile(filename, publicKeyFile, signatureFile string) error {
	// Чтение файла
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	// Чтение публичного ключа
	publicKeyData, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(publicKeyData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return fmt.Errorf("failed to decode PEM block containing public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA public key")
	}

	// Чтение подписи
	signature, err := os.ReadFile(signatureFile)
	if err != nil {
		return err
	}

	// Создание хэша
	hashed := sha256.Sum256(data)

	// Верификация подписи
	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return err
	}

	return nil
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}
