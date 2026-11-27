<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Common\Helper;
use OpenPGP\Enum\HashAlgorithm;
use OpenPGP\Type\PublicKeyMaterialInterface;
use phpseclib4\Crypt\EC\Curves\Ed25519;

/**
 * EdDSALegacy public key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class EdDSALegacyPublicKeyMaterial extends ECPublicKeyMaterial implements
    PublicKeyMaterialInterface
{
    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $length = ord($bytes[0]);
        return new self(
            substr($bytes, 1, $length),
            Helper::readMPI(substr($bytes, $length + 1)),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function verify(
        HashAlgorithm $hash,
        string $message,
        string $signature,
    ): bool {
        // R (MPI of an EC point R) and S (MPI of EdDSA value S) are read
        // only while the signature holds their length and their value;
        // a value longer than 32 octets is not a valid R or S.
        $mpis = [];
        $offset = 0;
        foreach (["r", "s"] as $_) {
            if (strlen($signature) < $offset + 2) {
                return false;
            }
            $length = Helper::bit2ByteLength(
                Helper::bytesToShort(substr($signature, $offset, 2)),
            );
            $value = substr($signature, $offset + 2, $length);
            if ($length > Ed25519::SIZE || strlen($value) !== $length) {
                return false;
            }
            $mpis[] = $value;
            $offset += 2 + $length;
        }
        [$r, $s] = $mpis;

        // R and S are octet strings stored as MPIs, which strip leading zero
        // octets (RFC 9580, section 11.3.1): zero-fill them back to their
        // native length before verifying.
        return $this->getPublicKey()->verify(
            $hash->hash($message),
            implode([
                str_pad($r, Ed25519::SIZE, "\0", STR_PAD_LEFT),
                str_pad($s, Ed25519::SIZE, "\0", STR_PAD_LEFT),
            ]),
        );
    }
}
