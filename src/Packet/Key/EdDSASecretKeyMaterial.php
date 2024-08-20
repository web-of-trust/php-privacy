<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\PrivateKey;
use phpseclib3\Crypt\EC\Formats\Keys\PKCS8;
use phpseclib3\File\ASN1;
use phpseclib3\Math\BigInteger;
use OpenPGP\Common\Helper;
use OpenPGP\Enum\{
    CurveOid,
    HashAlgorithm,
};
use OpenPGP\Type\{
    KeyMaterialInterface,
    SecretKeyMaterialInterface,
};

/**
 * EdDSA secret key material class
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class EdDSASecretKeyMaterial extends ECSecretKeyMaterial implements SecretKeyMaterialInterface
{
    const ED25519_KEY_LENGTH = 32;
    const SIGNATURE_LENGTH   = 64;

    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @param KeyMaterialInterface $publicMaterial
     * @return self
     */
    public static function fromBytes(
        string $bytes, KeyMaterialInterface $publicMaterial
    ): self
    {
        return new self(
            Helper::readMPI($bytes),
            $publicMaterial
        );
    }

    /**
     * Generate key material by using EC create key
     *
     * @return self
     */
    public static function generate(): self
    {
        $curve = CurveOid::Ed25519;
        do {
            $privateKey = EC::createKey($curve->name);
            $params = PKCS8::load($privateKey->toString('PKCS8'));
            $d = Helper::bin2BigInt($params['secret']);
        } while ($d->getLengthInBytes() !== self::ED25519_KEY_LENGTH);
        return new self(
            $d,
            new EdDSAPublicKeyMaterial(
                ASN1::encodeOID($curve->value),
                Helper::bin2BigInt(
                    "\x40" . $privateKey->getEncodedCoordinates()
                ),
                $privateKey->getPublicKey()
            ),
            $privateKey,
        );
    }

    /**
     * {@inheritdoc}
     */
    public function sign(HashAlgorithm $hash, string $message): string
    {
        $signature = $this->getPrivateKey()->sign(
            $hash->hash($message)
        );
        $length = intval(self::SIGNATURE_LENGTH / 2);
        return implode([
            pack('n', $length * 8), // r bit length
            substr($signature, 0, $length), // r
            pack('n', $length * 8), // s bit length
            substr($signature, $length, $length), // s
        ]);
    }
}
