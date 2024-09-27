<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP;

use DateTimeInterface;
use OpenPGP\Enum\{
    CompressionAlgorithm,
    CurveOid,
    DHKeySize,
    KeyType,
    RevocationReasonTag,
    RSAKeySize,
    SymmetricAlgorithm
};
use OpenPGP\Key\{PrivateKey, PublicKey};
use OpenPGP\Message\{
    CleartextMessage,
    EncryptedMessage,
    LiteralMessage,
    Signature,
    SignedMessage
};
use OpenPGP\Type\{
    CleartextMessageInterface,
    EncryptedMessageInterface,
    KeyInterface,
    LiteralMessageInterface,
    NotationDataInterface,
    PrivateKeyInterface,
    SignatureInterface,
    SignedMessageInterface
};

/**
 * OpenPGP class
 * Export high level API for developers.
 *
 * @package OpenPGP
 * @author  Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
final class OpenPGP
{
    /**
     * Generate a new OpenPGP key pair. Support RSA, DSA and ECC key types.
     * The generated primary key will have signing capabilities.
     * One subkey with encryption capabilities is also generated.
     *
     * @param array $userIDs
     * @param string $passphrase
     * @param KeyType $type
     * @param RSAKeySize $rsaKeySize
     * @param DHKeySize $dhKeySize
     * @param CurveOid $curve
     * @param int $keyExpiry
     * @param DateTimeInterface $time
     * @return PrivateKeyInterface
     */
    public static function generateKey(
        array $userIDs,
        string $passphrase,
        KeyType $type = KeyType::Rsa,
        RSAKeySize $rsaKeySize = RSAKeySize::S2048,
        DHKeySize $dhKeySize = DHKeySize::L2048_N224,
        CurveOid $curve = CurveOid::Ed25519,
        int $keyExpiry = 0,
        ?DateTimeInterface $time = null
    ): PrivateKeyInterface {
        return PrivateKey::generate(
            $userIDs,
            $passphrase,
            $type,
            $rsaKeySize,
            $dhKeySize,
            $curve,
            $keyExpiry,
            $time
        );
    }

    /**
     * Read OpenPGP private key from armored/binary string.
     * Return a private key object.
     *
     * @param string $privateKey
     * @param bool $armored
     * @return PrivateKeyInterface
     */
    public static function readPrivateKey(
        string $privateKey,
        bool $armored = true
    ): PrivateKeyInterface {
        return $armored
            ? PrivateKey::fromArmored($privateKey)
            : PrivateKey::fromBytes($privateKey);
    }

    /**
     * Read OpenPGP public key from armored/binary string.
     * Return a public key object.
     *
     * @param string $publicKey
     * @param bool $armored
     * @return KeyInterface
     */
    public static function readPublicKey(
        string $publicKey,
        bool $armored = true
    ): KeyInterface {
        return $armored
            ? PublicKey::fromArmored($publicKey)
            : PublicKey::fromBytes($publicKey);
    }

    /**
     * Read OpenPGP public key list from armored/binary string.
     * Return array of public key objects.
     *
     * @param string $publicKeys
     * @param bool $armored
     * @return array
     */
    public static function readPublicKeys(
        string $publicKeys,
        bool $armored = true
    ): array {
        return PublicKey::readPublicKeys($publicKeys, $armored);
    }

    /**
     * Lock a private key with the given passphrase.
     * The private key must be decrypted.
     *
     * @param PrivateKeyInterface $privateKey
     * @param string $passphrase
     * @param array $subkeyPassphrases
     * @return PrivateKeyInterface
     */
    public static function encryptPrivateKey(
        PrivateKeyInterface $privateKey,
        string $passphrase,
        array $subkeyPassphrases = []
    ): PrivateKeyInterface {
        return $privateKey->encrypt($passphrase, $subkeyPassphrases);
    }

    /**
     * Read an armored & unlock OpenPGP private key with the given passphrase.
     *
     * @param string $armoredPrivateKey
     * @param string $passphrase
     * @param array $subkeyPassphrases
     * @return PrivateKeyInterface
     */
    public static function decryptPrivateKey(
        string $armoredPrivateKey,
        string $passphrase,
        array $subkeyPassphrases = []
    ): PrivateKeyInterface {
        return self::readPrivateKey($armoredPrivateKey)->decrypt(
            $passphrase,
            $subkeyPassphrases
        );
    }

    /**
     * Certify an OpenPGP key by a private key.
     * Return clone of the key object with the new certification added.
     *
     * @param PrivateKeyInterface $privateKey
     * @param KeyInterface $key
     * @param DateTimeInterface $time
     * @return KeyInterface
     */
    public static function certifyKey(
        PrivateKeyInterface $privateKey,
        KeyInterface $key,
        ?DateTimeInterface $time = null
    ): KeyInterface {
        return $privateKey->certifyKey($key, $time);
    }

    /**
     * Revoke an OpenPGP key by a private key.
     * Return clone of the key object with the new revocation signature added.
     *
     * @param PrivateKeyInterface $privateKey
     * @param KeyInterface $key
     * @param string $revocationReason
     * @param RevocationReasonTag $reasonTag
     * @param DateTimeInterface $time
     * @return KeyInterface
     */
    public static function revokeKey(
        PrivateKeyInterface $privateKey,
        KeyInterface $key,
        string $revocationReason = "",
        RevocationReasonTag $reasonTag = RevocationReasonTag::NoReason,
        ?DateTimeInterface $time = null
    ): KeyInterface {
        return $privateKey->revokeKey(
            $key,
            $revocationReason,
            $reasonTag,
            $time
        );
    }

    /**
     * Read OpenPGP signature from armored/binary string.
     * Return a signature object.
     *
     * @param string $signature
     * @param bool $armored
     * @return SignatureInterface
     */
    public static function readSignature(
        string $signature,
        bool $armored = true
    ): SignatureInterface {
        return $armored
            ? Signature::fromArmored($signature)
            : Signature::fromBytes($signature);
    }

    /**
     * Read OpenPGP signed message from armored string.
     * Return a signed message object.
     *
     * @param string $signedMessage
     * @return SignedMessageInterface
     */
    public static function readSignedMessage(
        string $signedMessage
    ): SignedMessageInterface {
        return SignedMessage::fromArmored($signedMessage);
    }

    /**
     * Read OpenPGP encrypted message from armored/binary string.
     * Return an encrypted message object.
     *
     * @param string $message
     * @param bool $armored
     * @return EncryptedMessageInterface
     */
    public static function readEncryptedMessage(
        string $message,
        bool $armored = true
    ): EncryptedMessageInterface {
        return $armored
            ? EncryptedMessage::fromArmored($message)
            : EncryptedMessage::fromBytes($message);
    }

    /**
     * Read OpenPGP literal message from armored/binary string.
     * Return a literal message object.
     *
     * @param string $message
     * @param bool $armored
     * @return LiteralMessageInterface
     */
    public static function readLiteralMessage(
        string $message,
        bool $armored = true
    ): LiteralMessageInterface {
        return $armored
            ? LiteralMessage::fromArmored($message)
            : LiteralMessage::fromBytes($message);
    }

    /**
     * Create new cleartext message object from text.
     *
     * @param string $text
     * @return CleartextMessageInterface
     */
    public static function createCleartextMessage(
        string $text
    ): CleartextMessageInterface {
        return new CleartextMessage($text);
    }

    /**
     * Create new literal message object from literal data.
     *
     * @param string $literalData
     * @param string $filename
     * @param DateTimeInterface $time
     * @return LiteralMessageInterface
     */
    public static function createLiteralMessage(
        string $literalData,
        string $filename = "",
        ?DateTimeInterface $time = null
    ): LiteralMessageInterface {
        return LiteralMessage::fromLiteralData($literalData, $filename, $time);
    }

    /**
     * Sign a cleartext message.
     * Return a signed message object
     *
     * @param string $text
     * @param array $signingKeys
     * @param NotationDataInterface $notationData
     * @param DateTimeInterface $time
     * @return SignedMessageInterface
     */
    public static function signCleartext(
        string $text,
        array $signingKeys,
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null
    ): SignedMessageInterface {
        return self::createCleartextMessage($text)->sign(
            $signingKeys,
            $notationData,
            $time
        );
    }

    /**
     * Sign a cleartext message & return detached signature.
     *
     * @param string $text
     * @param array $signingKeys
     * @param NotationDataInterface $notationData
     * @param DateTimeInterface $time
     * @return SignatureInterface
     */
    public static function signDetachedCleartext(
        string $text,
        array $signingKeys,
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null
    ): SignatureInterface {
        return self::createCleartextMessage($text)->signDetached(
            $signingKeys,
            $notationData,
            $time
        );
    }

    /**
     * Sign a message & return signed literal message.
     *
     * @param LiteralMessageInterface $message
     * @param array $signingKeys
     * @param NotationDataInterface $notationData
     * @param DateTimeInterface $time
     * @return LiteralMessageInterface
     */
    public static function sign(
        LiteralMessageInterface $message,
        array $signingKeys,
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null
    ): LiteralMessageInterface {
        return $message->sign($signingKeys, $notationData, $time);
    }

    /**
     * Sign a message & return detached signature.
     *
     * @param LiteralMessageInterface $message
     * @param array $signingKeys
     * @param NotationDataInterface $notationData
     * @param DateTimeInterface $time
     * @return SignatureInterface
     */
    public static function signDetached(
        LiteralMessageInterface $message,
        array $signingKeys,
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null
    ): SignatureInterface {
        return $message->signDetached($signingKeys, $notationData, $time);
    }

    /**
     * Verify signatures of cleartext signed message.
     * Return verification array.
     *
     * @param string $armoredSignedMessage
     * @param array $verificationKeys
     * @param DateTimeInterface $time
     * @return array
     */
    public static function verify(
        string $armoredSignedMessage,
        array $verificationKeys,
        ?DateTimeInterface $time = null
    ): array {
        return self::readSignedMessage($armoredSignedMessage)->verify(
            $verificationKeys,
            $time
        );
    }

    /**
     * Verify detached signatures of cleartext message.
     * Return verification array.
     *
     * @param string $text
     * @param string $signature
     * @param array $verificationKeys
     * @param bool $armored
     * @param DateTimeInterface $time
     * @return array
     */
    public static function verifyDetached(
        string $text,
        string $signature,
        array $verificationKeys,
        bool $armored = true,
        ?DateTimeInterface $time = null
    ): array {
        return self::createCleartextMessage($text)->verifyDetached(
            $verificationKeys,
            self::readSignature($signature, $armored),
            $time
        );
    }

    /**
     * Encrypt a message using public keys, passwords or both at once.
     * At least one of `encryptionKeys`, `passwords`must be specified.
     * If signing keys are specified, those will be used to sign the message.
     *
     * @param LiteralMessageInterface $message
     * @param array $encryptionKeys
     * @param array $passwords
     * @param array $signingKeys
     * @param SymmetricAlgorithm $symmetric
     * @param CompressionAlgorithm $compression
     * @param NotationDataInterface $notationData
     * @param DateTimeInterface $time
     * @return EncryptedMessageInterface
     */
    public static function encrypt(
        LiteralMessageInterface $message,
        array $encryptionKeys = [],
        array $passwords = [],
        array $signingKeys = [],
        ?SymmetricAlgorithm $symmetric = null,
        ?CompressionAlgorithm $compression = null,
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null
    ): EncryptedMessageInterface {
        if (!empty($signingKeys)) {
            return $message
                ->sign($signingKeys, $notationData, $time)
                ->compress($compression)
                ->encrypt($encryptionKeys, $passwords, $symmetric);
        } else {
            return $message
                ->compress($compression)
                ->encrypt($encryptionKeys, $passwords, $symmetric);
        }
    }

    /**
     * Decrypt a message with the user's private key, or a password.
     * One of `decryptionKeys` or `passwords` must be specified
     *
     * @param EncryptedMessageInterface $message
     * @param array $decryptionKeys
     * @param array $passwords
     * @return LiteralMessageInterface
     */
    public static function decrypt(
        EncryptedMessageInterface $message,
        array $decryptionKeys = [],
        array $passwords = []
    ): LiteralMessageInterface {
        return $message->decrypt($decryptionKeys, $passwords);
    }
}
