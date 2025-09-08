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
        $bitLength = Helper::bytesToShort($signature);
        $r = substr($signature, 2, Helper::bit2ByteLength($bitLength)); // MPI of an EC point R

        $bitLength = Helper::bytesToShort(substr($signature, strlen($r) + 2));
        $s = substr(
            $signature,
            strlen($r) + 4,
            Helper::bit2ByteLength($bitLength),
        ); // MPI of EdDSA value S

        return $this->getPublicKey()->verify(
            $hash->hash($message),
            implode([$r, $s]),
        );
    }
}
