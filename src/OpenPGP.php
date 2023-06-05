<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
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
    RSAKeySize,
    SymmetricAlgorithm,
};
use OpenPGP\Key\{
    PrivateKey,
    PublicKey,
};
use OpenPGP\Message\{
    CleartextMessage,
    EncryptedMessage,
    LiteralMessage,
    Signature,
    SignedMessage,
};
use OpenPGP\Type\{
    CleartextMessageInterface,
    EncryptedMessageInterface,
    KeyInterface,
    LiteralMessageInterface,
    NotationDataInterface,
    PrivateKeyInterface,
    SignatureInterface,
    SignedMessageInterface,
};

/**
 * OpenPGP class
 *
 * @package   OpenPGP
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
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
        RSAKeySize $rsaKeySize = RSAKeySize::S4096,
        DHKeySize $dhKeySize = DHKeySize::L2048_N224,
        CurveOid $curve = CurveOid::Secp521r1,
        int $keyExpiry = 0,
        ?DateTimeInterface $time = null
    ): PrivateKeyInterface
    {
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
    ): PrivateKeyInterface
    {
        return self::readPrivateKey($armoredPrivateKey)->decrypt(
            $passphrase, $subkeyPassphrases
        );
    }

    /**
     * Read an armored OpenPGP private key.
     * Return a private key object.
     *
     * @param string $armoredPrivateKey
     * @return PrivateKeyInterface
     */
    public static function readPrivateKey(
        string $armoredPrivateKey
    ): PrivateKeyInterface
    {
        return PrivateKey::fromArmored($armoredPrivateKey);
    }

    /**
     * Read an armored OpenPGP public key.
     * Return a public key object.
     *
     * @param string $armoredPublicKey
     * @return KeyInterface
     */
    public static function readPublicKey(
        string $armoredPublicKey
    ): KeyInterface
    {
        return PublicKey::fromArmored($armoredPublicKey);
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
    ): KeyInterface
    {
        return $privateKey->certifyKey($key, $time);
    }

    /**
     * Revoke an OpenPGP key by a private key.
     * Return clone of the key object with the new revocation signature added.
     * 
     * @param PrivateKeyInterface $privateKey
     * @param KeyInterface $key
     * @param string $revocationReason
     * @param DateTimeInterface $time
     * @return KeyInterface
     */
    public function revokeKey(
        PrivateKeyInterface $privateKey,
        KeyInterface $key,
        string $revocationReason = '',
        ?DateTimeInterface $time = null
    ): KeyInterface
    {
        return $privateKey->revokeKey($key, $revocationReason, $time);
    }

    /**
     * Read an armored OpenPGP signature.
     * Return a signature object.
     *
     * @param string $armoredSignature
     * @return SignatureInterface
     */
    public static function readSignature(
        string $armoredSignature
    ): SignatureInterface
    {
        return Signature::fromArmored($armoredSignature);
    }

    /**
     * Read an armored OpenPGP signed message.
     * Return a signed message object.
     *
     * @param string $armoredSignedMessage
     * @return SignedMessageInterface
     */
    public static function readSignedMessage(
        string $armoredSignedMessage
    ): SignedMessageInterface
    {
        return SignedMessage::fromArmored($armoredSignedMessage);
    }

    /**
     * Read an armored OpenPGP message.
     * Return an encrypted message object.
     *
     * @param string $armoredMessage
     * @return EncryptedMessageInterface
     */
    public static function readEncryptedMessage(
        string $armoredMessage
    ): EncryptedMessageInterface
    {
        return EncryptedMessage::fromArmored($armoredMessage);
    }

    /**
     * Read an armored OpenPGP message.
     * Return a literal message object.
     *
     * @param string $armoredMessage
     * @return LiteralMessageInterface
     */
    public static function readLiteralMessage(
        string $armoredMessage
    ): LiteralMessageInterface
    {
        return LiteralMessage::fromArmored($armoredMessage);
    }

    /**
     * Create new cleartext message object from text.
     *
     * @param string $text
     * @return CleartextMessageInterface
     */
    public static function createCleartextMessage(
        string $text
    ): CleartextMessageInterface
    {
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
        string $filename = '',
        ?DateTimeInterface $time = null
    ): LiteralMessageInterface
    {
        return LiteralMessage::fromLiteralData(
            $literalData, $filename, $time
        );
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
    ): SignedMessageInterface
    {
        return self::createCleartextMessage($text)->sign(
            $signingKeys, $notationData, $time
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
    ): SignatureInterface
    {
        return self::createCleartextMessage($text)->signDetached(
            $signingKeys, $notationData, $time
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
    ): LiteralMessageInterface
    {
        return $message->sign(
            $signingKeys, $notationData, $time
        );
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
    ): SignatureInterface
    {
        return $message->signDetached(
            $signingKeys, $notationData, $time
        );
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
    ): array
    {
        return self::readSignedMessage($armoredSignedMessage)
            ->verify($verificationKeys, $time);
    }

    /**
     * Verify detached signatures of cleartext message.
     * Return verification array.
     *
     * @param string $text
     * @param string $armoredSignature
     * @param array $verificationKeys
     * @param DateTimeInterface $time
     * @return array
     */
    public static function verifyDetached(
        string $text,
        string $armoredSignature,
        array $verificationKeys,
        ?DateTimeInterface $time = null
    ): array
    {
        return self::createCleartextMessage($text)->verifyDetached(
            $verificationKeys, self::readSignature($armoredSignature), $time
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
    ): EncryptedMessageInterface
    {
        if (!empty($signingKeys)) {
            return $message->sign($signingKeys, $notationData, $time)
                ->compress($compression)
                ->encrypt($encryptionKeys, $passwords, $symmetric);
        }
        else {
            return $message->compress($compression)
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
    ): LiteralMessageInterface
    {
        return $message->decrypt(
            $decryptionKeys, $passwords
        );
    }
}
