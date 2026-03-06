<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\MontgomeryCurve;
use OpenPGP\Type\{SecretKeyPacketInterface, SessionKeyCryptorInterface};
use phpseclib3\Crypt\{DH, EC};

/**
 * Montgomery session key cryptor class.
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class MontgomerySessionKeyCryptor implements SessionKeyCryptorInterface
{
    /**
     * Constructor
     *
     * @param string $ephemeralKey
     * @param string $wrappedKey
     * @param MontgomeryCurve $curve
     * @return self
     */
    public function __construct(
        private readonly string $ephemeralKey,
        private readonly string $wrappedKey,
        private readonly MontgomeryCurve $curve = MontgomeryCurve::Curve25519,
    ) {}

    /**
     * Read encrypted session key from byte string
     *
     * @param string $bytes
     * @param MontgomeryCurve $curve
     * @return self
     */
    public static function fromBytes(
        string $bytes,
        MontgomeryCurve $curve = MontgomeryCurve::Curve25519,
    ): self {
        return new self(
            substr($bytes, 0, $curve->payloadSize()),
            substr(
                $bytes,
                $curve->payloadSize() + 1,
                ord($bytes[$curve->payloadSize()]),
            ),
            $curve,
        );
    }

    /**
     * Produce cryptor by encrypting session key
     *
     * @param string $sessionKey
     * @param EC $publicKey
     * @return self
     */
    public static function encryptSessionKey(
        string $sessionKey,
        EC $publicKey,
    ): self {
        $publicCurve = $publicKey->getCurve();
        switch ($publicCurve) {
            case MontgomeryCurve::Curve25519->name:
            case MontgomeryCurve::Curve448->name:
                $curve = constant(MontgomeryCurve::class . "::" . $publicCurve);
                $privateKey = EC::createKey($publicCurve);
                $ephemeralKey = $privateKey->getPublicKey()->getEncodedCoordinates();

                $kek = hash_hkdf(
                    $curve->hkdfHash(),
                    implode([
                        $ephemeralKey,
                        $publicKey->getEncodedCoordinates(),
                        self::computeSecret(
                            $privateKey,
                            $publicKey,
                        ),
                    ]),
                    $curve->kekSize()->value,
                    $curve->hkdfInfo(),
                );
                $keyWrapper = new AesKeyWrapper($curve->kekSize());

                return new self(
                    $ephemeralKey,
                    $keyWrapper->wrap($kek, $sessionKey),
                    $curve,
                );
            default:
                throw new \InvalidArgumentException(
                    "{$publicCurve} is not Montgomery Curve.",
                );
        }
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            $this->ephemeralKey,
            chr(strlen($this->wrappedKey)),
            $this->wrappedKey,
        ]);
    }

    /**
     * Get ephemeral key
     *
     * @return string
     */
    public function getEphemeralKey(): string
    {
        return $this->ephemeralKey;
    }

    /**
     * Get wrapped key
     *
     * @return string
     */
    public function getWrappedKey(): string
    {
        return $this->wrappedKey;
    }

    /**
     * {@inheritdoc}
     */
    public function decryptSessionKey(
        SecretKeyPacketInterface $secretKey,
    ): string {
        return $this->decrypt($secretKey->getECKeyMaterial()->getECKey());
    }

    /**
     * Decrypt session key by using private key
     *
     * @param EC $privateKey
     * @return string
     */
    private function decrypt(EC $privateKey): string
    {
        $curve = $privateKey->getCurve();
        switch ($curve) {
            case MontgomeryCurve::Curve25519->name:
            case MontgomeryCurve::Curve448->name:
                if ($curve != $this->curve->name) {
                    throw new \InvalidArgumentException(
                        "Private {$curve} is not match ephemeral {$this->curve->name}.",
                    );
                }
                $kek = hash_hkdf(
                    $this->curve->hkdfHash(),
                    implode([
                        $this->ephemeralKey,
                        $privateKey->getEncodedCoordinates(),
                        self::computeSecret(
                            $privateKey,
                            EC::loadFormat(
                                "MontgomeryPublic",
                                $this->ephemeralKey,
                            ),
                        ),
                    ]),
                    $this->curve->kekSize()->value,
                    $this->curve->hkdfInfo(),
                );
                $keyWrapper = new AesKeyWrapper($this->curve->kekSize());
                return $keyWrapper->unwrap($kek, $this->wrappedKey);
            default:
                throw new \InvalidArgumentException(
                    "{$curve} is not Montgomery Curve.",
                );
        }
    }

    /**
     * Compute shared secret
     *
     * @return string
     */
    private static function computeSecret(
        EC $privateKey,
        EC $publicKey,
    ): string {
        if (
            extension_loaded("sodium") &&
            $privateKey->getCurve() == "Curve25519" &&
            $publicKey->getCurve() == "Curve25519"
        ) {
            return sodium_crypto_scalarmult(
                $privateKey->toString("MontgomeryPrivate"),
                $publicKey->getEncodedCoordinates(),
            );
        }
        return DH::computeSecret(
            $privateKey,
            $publicKey->getEncodedCoordinates(),
        );
    }
}
