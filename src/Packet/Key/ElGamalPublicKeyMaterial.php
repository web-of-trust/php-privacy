<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Common\Helper;
use OpenPGP\Cryptor\Asymmetric\ElGamal\PublicKey;
use OpenPGP\Type\KeyMaterialInterface;
use phpseclib4\Crypt\Common\AsymmetricKey;
use phpseclib4\Math\BigInteger;

/**
 * ElGamal public key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class ElGamalPublicKeyMaterial implements KeyMaterialInterface
{
    /**
     * Constructor
     *
     * @param PublicKey $publicKey
     * @return self
     */
    public function __construct(
        private readonly PublicKey $publicKey,
    ) {
    }

    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $prime = Helper::readMPI($bytes);

        $offset = $prime->getLengthInBytes() + 2;
        $generator = Helper::readMPI(substr($bytes, $offset));

        $offset += $generator->getLengthInBytes() + 2;
        $exponent = Helper::readMPI(substr($bytes, $offset));

        return new self(new PublicKey($exponent, $prime, $generator));
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyLength(): int
    {
        return $this->publicKey->getBitSize();
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicKey(): PublicKey
    {
        return $this->publicKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicMaterial(): KeyMaterialInterface
    {
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getParameters(): array
    {
        return [
            "p" => $this->publicKey->getPrime(),
            "g" => $this->publicKey->getGenerator(),
            "y" => $this->publicKey->getY(),
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            pack("n", $this->publicKey->getPrime()->getLength()),
            $this->publicKey->getPrime()->toBytes(),
            pack("n", $this->publicKey->getGenerator()->getLength()),
            $this->publicKey->getGenerator()->toBytes(),
            pack("n", $this->publicKey->getY()->getLength()),
            $this->publicKey->getY()->toBytes(),
        ]);
    }
}
