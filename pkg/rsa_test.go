package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	// this must match the test-data/pub.pem file since the tests are leveraging the same E & N in their verification
	pubKey = "-----BEGIN RSA PUBLIC KEY----- MIIBigKCAYEA2J4T3lg5fjZrOGlMLe2UVO8bvYaKI8g3LEF+jaSiZNN8LFaU7Cwg pghCdGfl4aEISeKfmvkyzUpWYFc+JB+AhZGRH05Ngnzj1uxQajLSG+XUomlTtybn 3XgYsRC0NYneiz55wBlLI71b409nZmAjDUjgvS+jzIyP6KOopIphIOLvDkrRh3tV Q4tF3dxSGCsRY/BVFn4J2kx+6MN0iWVVT+o/2VH3KC1Qlke1RcvDhGHl3coPjLAH y2Yv7T3b5f9vTo+9G/jlZxu3hwqCdW4w2yx6hGn740Fjdfk/aoTLCZV1Vnj+COKr F8wRMoaBBviCsnKebIgse4QpMCOYCOUBw5b3enQ50pi2dPnO1YNKHIrob7AmYzYW ZofczPRySG3GvUasXI/LHPebBqn6r5N3SFexRGdk/c2+CriHmJn7AjTceqkthQDt GiV0QnshJOXSD9iF/HupBuhVZH4pZ92PYkMXq/rk7iemwkRhCVXq16rl5BP8a+b+ dzWbgUNFx869AgMBAAE= -----END RSA PUBLIC KEY-----"
	// this must match the test-data/key.pem file since the tests are leveraging the same E, N, & D in their verification
	privKey = "-----BEGIN RSA PRIVATE KEY----- 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 -----END RSA PRIVATE KEY-----"
	// these must match the E, N, & D from the key in test-data/key.pem (and E & N from the key in test-data/pub.pem)
	keyE = 65537
	keyN = "4915868251941644664796946965940485199038305661288248515808994130978937020630830759575542430655177530563586654159989583258973528670591515098417027856097286204329030722956958090130805359874473066975655997698035263329861714526090491134718829688268688121566634080749352585325160298851576120617530085351287924613553002937366458529338424405037295469297276921750694649617108069509647620605537534836435958749725134062604914688746546550659891398909927923483645350545482535677728750036657388198860243572825931751297441544636818194344905189917696772704534851061607103825823954998924817982585662277133796608369444589146115991405193638592561278734769230045740307698364604603399268027473404371146590843317821691069221075362855922014474839482719672290355442082748636881234423855939152062524620583138458337460012455712150728398874134591697933096511522057320024232661637387665069496092673758402975366735977483324768429761220210594782814654141"
	keyD = "27325797704843693659849059000139139081887403335631916845586715319828902095241034006948290393025026693078941942879353726616171879925789843147433102643945273116515340836065426129280442995594405271819452827584330171217306599353872864494530870430997498858457433138791661913635898757520624696598352229938419380452528479638717073443062514469003566526771106132318813202549895016896785452287979674701521579756852866914978873325150173312867516618442814631812441845121370922235344193566070428348917353716190186099325148433930650614944299299247557398017989971765245426865190815553924391113849560551038801220964983923882933055035180915112740193823405385798582501833004841741126865053293639764585728016164660085486119525383280348276674737435488862929142636733846599241365029129462203634727477222287944865940666468648872645564825313484178456793945634054733451028788585012206774996176341003123382470289123383776690402536588734563782793443"
)

func TestReadPublicKeyFromPEMFile(t *testing.T) {
	t.Parallel()

	t.Run("should be able to read a public key from a file", func(t *testing.T) {
		pubKey, err := ReadPublicKeyFromPEMFile("../test-data/pub.pem")
		assert.Nil(t, err)
		assert.NotNil(t, pubKey)
		assert.Equal(t, keyE, pubKey.E)
		assert.Equal(t, keyN, pubKey.N.String())
	})

	t.Run("should be able to read a public key from a file containing multiple things", func(t *testing.T) {
		pubKey, err := ReadPublicKeyFromPEMFile("../test-data/multiple.pem")
		assert.Nil(t, err)
		assert.NotNil(t, pubKey)
		assert.Equal(t, keyE, pubKey.E)
		assert.Equal(t, keyN, pubKey.N.String())
	})

	t.Run("should return an error if the file is not found", func(t *testing.T) {
		pubKey, err := ReadPublicKeyFromPEMFile("../test-data/will-not-find.pem")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "public key")
		assert.Contains(t, err.Error(), "no such file")
		assert.Nil(t, pubKey)
	})

	t.Run("should return an error if the file contents are garbage", func(t *testing.T) {
		pubKey, err := ReadPublicKeyFromPEMFile("../test-data/garbage.pem")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "public key")
		assert.Contains(t, err.Error(), "not found")
		assert.Nil(t, pubKey)
	})

	t.Run("should return an error if the file does not contain a public key", func(t *testing.T) {
		pubKey, err := ReadPublicKeyFromPEMFile("../test-data/key.pem")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "public key")
		assert.Contains(t, err.Error(), "not found")
		assert.Nil(t, pubKey)
	})
}

func TestFormatPublicKeyForPEMFile(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(t, err)

	t.Run("should return the public key contents contents for a pem file", func(t *testing.T) {
		actual, err := FormatPublicKeyForPEMFile(&key.PublicKey)
		assert.Nil(t, err)
		assert.Contains(t, actual, pubKeyBeginArmor)
		assert.Contains(t, actual, pubKeyEndArmor)
		stripped := strings.ReplaceAll(actual, pubKeyBeginArmor, "")
		stripped = strings.ReplaceAll(stripped, pubKeyEndArmor, "")
		assert.NotContains(t, stripped, " ")
	})

	t.Run("should return an error if the key is nil", func(t *testing.T) {
		actual, err := FormatPublicKeyForPEMFile(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "public key")
		assert.Contains(t, err.Error(), "nil")
		assert.Equal(t, "", actual)
	})
}

func TestReadPublicKeyFromPEMEnvVar(t *testing.T) {
	t.Parallel()

	t.Run("should return the public key", func(t *testing.T) {
		actual, err := ReadPublicKeyFromPEMEnvVar(pubKey)
		assert.Nil(t, err)
		assert.NotNil(t, actual)
		assert.Equal(t, keyE, actual.E)
		assert.Equal(t, keyN, actual.N.String())
	})

	t.Run("should return an error if the pem did not contain a public key", func(t *testing.T) {
		actual, err := ReadPublicKeyFromPEMEnvVar(privKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "public key")
		assert.Contains(t, err.Error(), "not found")
		assert.Nil(t, actual)
	})

	t.Run("should not crash for invalid input", func(t *testing.T) {
		actual, err := ReadPublicKeyFromPEMEnvVar("garbage")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "public key")
		assert.Contains(t, err.Error(), "not found")
		assert.Nil(t, actual)
	})
}

func TestFormatPublicKeyForPEMEnvVar(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(t, err)

	t.Run("should return the public key contents contents for a pem file with the newlines converted to spaces", func(t *testing.T) {
		actual, err := FormatPublicKeyForPEMEnvVar(&key.PublicKey)
		assert.Nil(t, err)
		assert.Contains(t, actual, pubKeyBeginArmor)
		assert.Contains(t, actual, pubKeyEndArmor)
		assert.NotContains(t, actual, "\n")
	})

	t.Run("should return an error if the key is nil", func(t *testing.T) {
		actual, err := FormatPublicKeyForPEMEnvVar(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "public key")
		assert.Contains(t, err.Error(), "nil")
		assert.Equal(t, "", actual)
	})
}

func TestReadPrivateKeyFromPEMFile(t *testing.T) {
	t.Parallel()

	t.Run("should be able to read a private key from a file", func(t *testing.T) {
		privKey, err := ReadPrivateKeyFromPEMFile("../test-data/key.pem")
		assert.Nil(t, err)
		assert.NotNil(t, privKey)
		assert.Equal(t, keyE, privKey.E)
		assert.Equal(t, keyN, privKey.N.String())
		assert.Equal(t, keyD, privKey.D.String())
	})

	t.Run("should be able to read a public key from a file containing multiple things", func(t *testing.T) {
		privKey, err := ReadPrivateKeyFromPEMFile("../test-data/multiple.pem")
		assert.Nil(t, err)
		assert.NotNil(t, privKey)
		assert.Equal(t, keyE, privKey.E)
		assert.Equal(t, keyN, privKey.N.String())
		assert.Equal(t, keyD, privKey.D.String())
	})

	t.Run("should return an error if the file is not found", func(t *testing.T) {
		privKey, err := ReadPrivateKeyFromPEMFile("../test-data/will-not-find.pem")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "private key")
		assert.Contains(t, err.Error(), "no such file")
		assert.Nil(t, privKey)
	})

	t.Run("should return an error if the file contents are garbage", func(t *testing.T) {
		privKey, err := ReadPrivateKeyFromPEMFile("../test-data/garbage.pem")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "private key")
		assert.Contains(t, err.Error(), "not found")
		assert.Nil(t, privKey)
	})

	t.Run("should return an error if the file does not contain a private key", func(t *testing.T) {
		privKey, err := ReadPrivateKeyFromPEMFile("../test-data/pub.pem")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "private key")
		assert.Contains(t, err.Error(), "not found")
		assert.Nil(t, privKey)
	})
}

func TestFormatPrivateKeyForPEMFile(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(t, err)

	t.Run("should return the private key contents contents for a pem file", func(t *testing.T) {
		actual, err := FormatPrivateKeyForPEMFile(key)
		assert.Nil(t, err)
		assert.Contains(t, actual, privKeyBeginArmor)
		assert.Contains(t, actual, privKeyEndArmor)
		stripped := strings.ReplaceAll(actual, privKeyBeginArmor, "")
		stripped = strings.ReplaceAll(stripped, privKeyEndArmor, "")
		assert.NotContains(t, stripped, " ")
	})

	t.Run("should return an error if the key is nil", func(t *testing.T) {
		actual, err := FormatPrivateKeyForPEMFile(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "private key")
		assert.Contains(t, err.Error(), "nil")
		assert.Equal(t, "", actual)
	})
}

func TestReadPrivateKeyFromPEMEnvVar(t *testing.T) {
	t.Parallel()

	t.Run("should return the private key", func(t *testing.T) {
		actual, err := ReadPrivateKeyFromPEMEnvVar(privKey)
		assert.Nil(t, err)
		assert.NotNil(t, actual)
		assert.Equal(t, keyE, actual.E)
		assert.Equal(t, keyN, actual.N.String())
		assert.Equal(t, keyD, actual.D.String())
	})

	t.Run("should return an error if the pem did not contain a public key", func(t *testing.T) {
		actual, err := ReadPrivateKeyFromPEMEnvVar(pubKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "private key")
		assert.Contains(t, err.Error(), "not found")
		assert.Nil(t, actual)
	})

	t.Run("should not crash for invalid input", func(t *testing.T) {
		actual, err := ReadPrivateKeyFromPEMEnvVar("garbage")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "private key")
		assert.Contains(t, err.Error(), "not found")
		assert.Nil(t, actual)
	})
}

func TestFormatPrivateKeyForPEMEnvVar(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(t, err)

	t.Run("should return the private key contents contents for a pem file with the newlines converted to spaces", func(t *testing.T) {
		actual, err := FormatPrivateKeyForPEMEnvVar(key)
		assert.Nil(t, err)
		assert.Contains(t, actual, privKeyBeginArmor)
		assert.Contains(t, actual, privKeyEndArmor)
		assert.NotContains(t, actual, "\n")
	})

	t.Run("should return an error if the key is nil", func(t *testing.T) {
		actual, err := FormatPrivateKeyForPEMEnvVar(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "private key")
		assert.Contains(t, err.Error(), "nil")
		assert.Equal(t, "", actual)
	})
}
