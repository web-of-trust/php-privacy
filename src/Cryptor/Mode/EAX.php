<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Cryptor\Mode;

use OpenPGP\Cryptor\Mac\CMac;
use OpenPGP\Enum\SymmetricAlgorithm;
use phpseclib3\Crypt\Common\BlockCipher;

/**
 * EAX class
 * A Two-Pass Authenticated-Encryption Scheme Optimized for Simplicity and
 * Efficiency - by M. Bellare, P. Rogaway, D. Wagner.
 *
 * https://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf
 *
 * EAX is an AEAD scheme based on CTR and OMAC1/CMAC, that uses a single block
 * cipher to encrypt and authenticate data. It's on-line (the length of a
 * message isn't needed to begin processing it), has good performances, it's
 * simple and provably secure (provided the underlying block cipher is secure).
 * 
 * @package  OpenPGP
 * @category Cryptor
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
final class EAX
{
    const N_TAG = "\x0";
    const H_TAG = "\x1";
    const C_TAG = "\x2";

    const CTR_MODE = 'ctr';

    private readonly BlockCipher $cipher;
    private readonly CMac $mac;

    private readonly string $zeroBlock;
    private readonly string $oneBlock;
    private readonly string $twoBlock;

    /**
     * Constructor
     *
     * @param SymmetricAlgorithm $symmetric - The symmetric cipher algorithm to use
     * @param string $key - The encryption key
     * @return self
     */
    public function __construct(
        SymmetricAlgorithm $symmetric,
        private readonly string $key
    )
    {
        $this->cipher = $this->cipherEngine($symmetric);
        $this->cipher->setKey($key);
        $this->mac = new CMac($symmetric);

        $tagLength = $this->mac->getMacSize();
        $this->zeroBlock = str_repeat(self::N_TAG, $tagLength);
        $this->oneBlock  = str_repeat(self::N_TAG, $tagLength - 1) . self::H_TAG;
        $this->twoBlock  = str_repeat(self::N_TAG, $tagLength - 1) . self::C_TAG;
    }

    /**
     * Encrypt plaintext input.
     *
     * @param string $plaintext - The cleartext input to be encrypted
     * @param string $nonce - The nonce (16 bytes)
     * @param string $adata - Associated data to sign
     * @return string The ciphertext output.
     */
    public function encrypt(
        string $plaintext, string $nonce, string $adata = ''
    ): string
    {
        $omacNonce = $this->omac($this->zeroBlock, $nonce);
        $omacAdata = $this->omac($this->oneBlock, $adata);

        $ciphered = $this->ctr($plaintext, $omacNonce);
        $omacCiphered = $this->omac($this->twoBlock, $ciphered);
        $tag = $omacCiphered ^ $omacAdata ^ $omacNonce;

        return implode([$ciphered, $tag]);
    }

    /**
     * Decrypt ciphertext input.
     *
     * @param string $ciphertext - The cleartext input to be encrypted
     * @param string $nonce - The ciphertext input to be decrypted
     * @param string $adata - Associated data to verify
     * @return string The plaintext output.
     */
    public function decrypt(
        string $ciphertext, string $nonce, string $adata = ''
    ): string
    {
        $length = strlen($ciphertext);
        $tagLength = $this->mac->getMacSize();

        if ($length < $tagLength) {
            throw new \LengthException('Invalid EAX ciphertext');
        }
        $ciphered = substr($ciphertext, 0, $length - $tagLength);
        $ctTag = substr($ciphertext, $length - $tagLength);

        $omacNonce = $this->omac($this->zeroBlock, $nonce);
        $omacAdata = $this->omac($this->oneBlock, $adata);
        $omacCiphered = $this->omac($this->twoBlock, $ciphered);
        $tag = $omacCiphered ^ $omacAdata ^ $omacNonce;

        if ($ctTag !== $tag) {
            throw new \UnexpectedValueException('Authentication tag mismatch');
        }

        return $this->ctr($ciphered, $omacNonce);
    }

    private function omac(string $tag, string $message): string
    {
        return $this->mac->generate(
            implode([$tag, $message]), $this->key
        );
    }

    private function ctr(string $plaintext, string $iv): string
    {
        $this->cipher->setIV($iv);
        return $this->cipher->encrypt($plaintext);
    }

    /**
     * Get block cipher engine
     *
     * @return BlockCipher
     */
    private function cipherEngine(SymmetricAlgorithm $symmetric): BlockCipher
    {
        return match($symmetric) {
            SymmetricAlgorithm::Plaintext => throw new \InvalidArgumentException(
                'Symmetric algorithm "Plaintext" is unsupported.'
            ),
            SymmetricAlgorithm::Idea => new \OpenPGP\Cryptor\Symmetric\IDEA(self::CTR_MODE),
            SymmetricAlgorithm::TripleDes => new \phpseclib3\Crypt\TripleDES(self::CTR_MODE),
            SymmetricAlgorithm::Cast5 => new \OpenPGP\Cryptor\Symmetric\CAST5(self::CTR_MODE),
            SymmetricAlgorithm::Blowfish => new \phpseclib3\Crypt\Blowfish(self::CTR_MODE),
            SymmetricAlgorithm::Aes128, SymmetricAlgorithm::Aes192, SymmetricAlgorithm::Aes256
                => new \phpseclib3\Crypt\AES(self::CTR_MODE),
            SymmetricAlgorithm::Twofish => new \phpseclib3\Crypt\Twofish(self::CTR_MODE),
            SymmetricAlgorithm::Camellia128, SymmetricAlgorithm::Camellia192, SymmetricAlgorithm::Camellia256
                => new \OpenPGP\Cryptor\Symmetric\Camellia(self::CTR_MODE),
        };
    }
}
