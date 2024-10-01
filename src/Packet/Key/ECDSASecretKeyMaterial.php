<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Common\Helper;
use OpenPGP\Enum\{Ecc, HashAlgorithm};
use OpenPGP\Type\{KeyMaterialInterface, SecretKeyMaterialInterface};
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\Formats\Keys\PKCS8;
use phpseclib3\File\ASN1;

/**
 * ECDSA secret key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class ECDSASecretKeyMaterial extends ECSecretKeyMaterial implements
    SecretKeyMaterialInterface
{
    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @param KeyMaterialInterface $publicMaterial
     * @return self
     */
    public static function fromBytes(
        string $bytes,
        KeyMaterialInterface $publicMaterial
    ): self {
        return new self(Helper::readMPI($bytes), $publicMaterial);
    }

    /**
     * Generate key material by using EC create key
     *
     * @param Ecc $curve
     * @return self
     */
    public static function generate(Ecc $curve): self
    {
        switch ($curve) {
            case Ecc::Ed25519:
            case Ecc::Curve25519:
                throw new \InvalidArgumentException(
                    "Curve {$curve->name} is not supported for ECDSA key generation."
                );
            default:
                $privateKey = EC::createKey($curve->name);
                $params = PKCS8::load($privateKey->toString("PKCS8"));
                return new self(
                    $params["dA"],
                    new ECDSAPublicKeyMaterial(
                        ASN1::encodeOID($curve->value),
                        Helper::bin2BigInt(
                            $privateKey->getEncodedCoordinates()
                        ),
                        $privateKey->getPublicKey()
                    ),
                    $privateKey
                );
        }
    }

    /**
     * {@inheritdoc}
     */
    public function sign(HashAlgorithm $hash, string $message): string
    {
        $signature = $this->privateKey
            ->withSignatureFormat("Raw")
            ->withHash(strtolower($hash->name))
            ->sign($message);
        return implode([
            pack("n", $signature["r"]->getLength()),
            $signature["r"]->toBytes(),
            pack("n", $signature["s"]->getLength()),
            $signature["s"]->toBytes(),
        ]);
    }
}
