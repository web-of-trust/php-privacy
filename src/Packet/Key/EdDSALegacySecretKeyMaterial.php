<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Common\Helper;
use OpenPGP\Enum\{
    CurveOid,
    HashAlgorithm,
};
use OpenPGP\Type\{
    KeyMaterialInterface,
    SecretKeyMaterialInterface,
};
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\Curves\Ed25519;
use phpseclib3\Crypt\EC\Formats\Keys\PKCS8;
use phpseclib3\File\ASN1;

/**
 * EdDSALegacy secret key material class
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class EdDSALegacySecretKeyMaterial extends ECSecretKeyMaterial implements SecretKeyMaterialInterface
{
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
        } while ($d->getLengthInBytes() !== Ed25519::SIZE);
        return new self(
            $d,
            new EdDSALegacyPublicKeyMaterial(
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
        $length = Helper::bit2ByteLength(
            $this->getPrivateKey()->getLength()
        );
        $r = substr($signature, 0, $length); // MPI of an EC point R
        $s = substr($signature, $length, Ed25519::SIZE); // MPI of EdDSA value S

        return implode([
            pack('n', strlen($r) * 8), // R bit length
            $r,
            pack('n', strlen($s) * 8), // S bit length
            $s,
        ]);
    }
}
