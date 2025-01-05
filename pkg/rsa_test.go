package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	// thise must match the test-data/rsa.pub.pem file since the tests are leveraging the same E & N in their verification
	pubKey = "-----BEGIN PUBLIC KEY----- MIIBCgKCAQEA+a94M4NZRYP2zSpaT0g5zmkG8bX9J3uL02h30GdWPkJxQEUQEZKu WqdyFwgB4vEfmTdGv8h0mkp8t2Ia8otnJehPCw0OvAByqdz/qWtle1X9wNu9U7j1 Br/sFYVxiOQdJRgB52Aj0YlT11jvSVB6t1x0xCWLQTA3P79zh8DLjv1koIzPR6sY gndSOa0PWQJsA72uM3PypO4eq8WsnrEBWLDLvnEOt3amgWyUDSsSrqeaGAqXXBTJ 4pQKrubN9LbN25nLgCGlLRdKh9wjdQ6YsVhfMm5jrH+dKEAPhkOKnweC/Qn70b3G vglgoKD4wQNxXNuhEsEAs//HDBJ8y2bSiwIDAQAB -----END PUBLIC KEY-----"
	// this must match the test-data/rsa.priv.pem file since the tests are leveraging the same E, N, & D in their verification
	privKey = "-----BEGIN PRIVATE KEY----- MIIEpAIBAAKCAQEAo9Kfvd0tGKh7d4DJCsm6+HgmECW+k4IHfyP4TlkWr7WTa1NU Q4W9zefvSjA18j6CEe4ABqpHnebgroAh7cZz5tFAtLBm7bVaZi8RwcOTuRk/6eDR 3hL5J9urd5i2E5Fr1RdQD6BMFo/S+r36Mi5XmGQFLbkUKSOAJCPBBJX0Y+sNDnN9 wc4lOkaFjzMNTUkbt80S3y0gaDUeYM9ywGlwSidWm7x+EptS2emmise+uKUSp1ws IaKWq+F2X7pi4bWCcumVvAvlqRCWYaKK3owawFZVlthUbhufeEBiR3UHqSPxOUNc ikP4ZyNamYKhMXV3/Lw7G+Ji4/JxlXbHG2KylQIDAQABAoIBAQCYvdiSfZV+WBhF 452OoWfiIqPailaV0baLpE3vPsEYMoOwnZEDI79EK+u/kBO8OOutK+p6TGlZn9n8 2RrJRy7pFlDuJ0rQdzZB78DumBsziYc92I/ULnx/3SCR8aBRvlR76bCL4TkQECj2 AAs2nl6thxQM/XL+qErhZzSfwfCK9y495/mbmjmgqvx110BYw+xKkhv9p+q33dgn 58P8JRJk1F9ONVv5B2T8wqOPOzguxkafuAj8wiVMfO71RFOmtKxD5EcrnrYTP53b 73GsChEtuaky525xGZQFrVanQWX7ht2/69XHNV9heUq/l9sqQxxbJyHlwmgeCvza /Pk9pVgBAoGBANkUNEZDNE5A4uWcZ4MjiEBpyh3HzqEcXjMZ35yQksrHMTfqxJlq a44L/dW95gzS0aKSsjjrhxL5AIs8Px118lFjUjXaAKOJFSTaG0g9fzzu/Co8JYb+ MyN0l4ygRalAeZvf3sX2Jl9XL1xvn56Gq3ExItCfCxh7SyBVSQMWqY91AoGBAMEx /hiTxHNzgSGngE1uT3t0F9giR3hCN8gx0lv4B2LFoZLZXq3278KkVB43RL0vO9pe zup6GX6tTjOozAJGQYlxH1azKcBXIHDx2roIxMAW4ygEW2KvOJFVgFyjiBC67am3 MwbYtgEAkO76FMVjzuRqHknJ2BqcubSz+JcyHFKhAoGAdj4tI0CkEyQA87U4JRSL uRpmv8YAZX3ASfGD/hI6Az5xLtYwdKilIWCiyXSBBOcozXc+oQaaMtlzVGRitLd0 YKTLOQ4gXvPikopDZhwpXJWIwbC1eEyqqltt2WnLyB+YnjFZdVdZG4GwCJe8yGru o99x6VVYg+NUzq3l8Uq83akCgYEAvyfE//JtpcI6md8PTw3/rOowkZVRXAdBBF9v gbpHLI7ZkOBtEvpLPy6zYHZVGE99DFNUrqKDSVkXEHxK51E2lVSNqo55mCtdGQPk 5L+6VUoQFs9A0MMI2Jxd9suD3PHoKE3xOiwA4br6rMpa9PgNhOoO7/m8TpCWGtsb 9BYL+iECgYAYE4nH2rGNLqPqstdq0V+puEQiVwi5pIQFsg16qKELRTiwV3du6dSn 9m/pvwU6cvHkBfINOny/RyyremT4oeb45F9HwI1HeagKbAp0mDlrOtEj3kbrrzoq uHl7w93dkGmsk1CGDkr1wrUY2s2fEp5MiwhmZv+CsvUpzmGh5kDB5g== -----END PRIVATE KEY-----"
	// these must match the E & N from the key in test-data/rsa.pub.pem
	pubKeyE = 65537
	pubKeyN = "31519865189678514929096824145126737278746270669723726982008111508928945722297890323881012298343825885119108906685842696352025809363907216694838289974827339883480486708931525512164105358563252506224194995652279283909069075396420050929830048835772858027662791419060234041626564273390734019709911042772847966793155362790508831340651225221122468142331056282563725956734028597074887254715496720280975451913550696588882207965927736526465816279982927025688348210446764503843345358702674462182619794606636847213980255595504568888437781518018039441579925183227928555626989521658188310366013085277305015128707928536814199427723"
	// these must match the E, N, & D from the key in test-data/rsa.priv.pem
	privKeyE = 65537
	privKeyN = "20680706270363516058686305304066270838427001278389769207791077689887967759454828074137493956477792043609682205973960948072806122097049818016002670351711972655584704144856147808274705524397954726875381708274022083550859287758758558172918482556592518367479981946544670803995629807135524710226786814799171506879296167639376906541400783414573447372887372706692022938047596516829599239905804172706618485849858018938288124703364002538810304345861071865973783113758431738257628772222897935563159571041170011849587441915171816108550279185840562812027108255893421432743681882930583973871317063052870634222068994722257292145301"
	privKeyD = "19281838899313247253459389341893364257003577919568006739290263685596142361928800748311601548997039916882463669588673722798430585541268780689531519129209582024609728276657308935056801598529267827807091015798340561717681705284208659819613515390360090366151896132896921812218273093599174541002755413453294715295709426728833996089900237377717614250091912513632553061955374867802661484073557973936144761898805181636015737032321977383971873097073967612059157600188193280565689066991702852895736058242013507913080569713340760325866102234608519031036607664656849474217923176570689010686165596826128341377521100970964984092673"
)

func TestReadPublicKeyFromPEMFile(t *testing.T) {
	t.Parallel()

	t.Run("should be able to read a public key from a file", func(t *testing.T) {
		pubKey, err := ReadPublicKeyFromPEMFile("../test-data/rsa-pub.pem")
		assert.Nil(t, err)
		assert.NotNil(t, pubKey)
		assert.Equal(t, pubKeyE, pubKey.E)
		assert.Equal(t, pubKeyN, pubKey.N.String())
	})

	t.Run("should be able to read a public key from a file containing multiple things", func(t *testing.T) {
		pubKey, err := ReadPublicKeyFromPEMFile("../test-data/rsa-multiple.pem")
		assert.Nil(t, err)
		assert.NotNil(t, pubKey)
		assert.Equal(t, pubKeyE, pubKey.E)
		assert.Equal(t, pubKeyN, pubKey.N.String())
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
		pubKey, err := ReadPublicKeyFromPEMFile("../test-data/rsa-priv.pem")
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
		assert.Equal(t, pubKeyE, actual.E)
		assert.Equal(t, pubKeyN, actual.N.String())
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
		privKey, err := ReadPrivateKeyFromPEMFile("../test-data/rsa-priv.pem")
		assert.Nil(t, err)
		assert.NotNil(t, privKey)
		assert.Equal(t, privKeyE, privKey.E)
		assert.Equal(t, privKeyN, privKey.N.String())
		assert.Equal(t, privKeyD, privKey.D.String())
	})

	t.Run("should be able to read a public key from a file containing multiple things", func(t *testing.T) {
		privKey, err := ReadPrivateKeyFromPEMFile("../test-data/rsa-multiple.pem")
		assert.Nil(t, err)
		assert.NotNil(t, privKey)
		assert.Equal(t, privKeyE, privKey.E)
		assert.Equal(t, privKeyN, privKey.N.String())
		assert.Equal(t, privKeyD, privKey.D.String())
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
		privKey, err := ReadPrivateKeyFromPEMFile("../test-data/rsa-pub.pem")
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
		assert.Equal(t, privKeyE, actual.E)
		assert.Equal(t, privKeyN, actual.N.String())
		assert.Equal(t, privKeyD, actual.D.String())
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
