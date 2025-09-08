<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Cryptor\Aead;

use OpenPGP\Cryptor\Symmetric\EcbCipher;
use OpenPGP\Enum\SymmetricAlgorithm;

/**
 * OCB Authenticated-Encryption class
 * An implementation of RFC 7253 on The OCB Authenticated-Encryption Algorithm.
 * For those still concerned about the original patents around this, please see:
 * https://mailarchive.ietf.org/arch/msg/cfrg/qLTveWOdTJcLn4HP3ev-vrj05Vg/
 *
 * see https://tools.ietf.org/html/rfc7253
 *
 * @package  OpenPGP
 * @category Cryptor
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
final class OCB implements AeadCipher
{
    const string ZERO_CHAR = "\x00";
    const string ONE_CHAR = "\x01";
    const string ZERO_BLOCK = "\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0";

    const int BLOCK_LENGTH = 16;
    const int IV_LENGTH = 15;
    const int TAG_LENGTH = 16;

    const string MASK_ASTERISK = "x";
    const string MASK_DOLLAR = '$';

    private readonly EcbCipher $encipher;

    private readonly EcbCipher $decipher;

    private array $mask;

    private int $maxNtz = 0;

    /**
     * Constructor
     *
     * @param string $key - The encryption key
     * @param SymmetricAlgorithm $symmetric - The symmetric cipher algorithm to use
     * @return self
     */
    public function __construct(
        string $key,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes256,
    ) {
        if ($symmetric->blockSize() !== self::BLOCK_LENGTH) {
            throw new \InvalidArgumentException(
                "Cipher must have a block size of " . self::BLOCK_LENGTH . ".",
            );
        }
        $this->encipher = $symmetric->ecbCipherEngine();
        $this->decipher = $symmetric->ecbCipherEngine();
        $this->encipher->setKey($key);
        $this->decipher->setKey($key);

        $maskAsterisk = $this->encipher->encryptBlock(self::ZERO_BLOCK);
        $maskDollar = self::double($maskAsterisk);

        $this->mask = [
            self::double($maskDollar),
            self::MASK_ASTERISK => $maskAsterisk,
            self::MASK_DOLLAR => $maskDollar,
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(
        string $plainText,
        string $nonce,
        string $aData = "",
    ): string {
        return $this->crypt($this->encipher, $plainText, $nonce, $aData);
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(
        string $cipherText,
        string $nonce,
        string $aData = "",
    ): string {
        $length = strlen($cipherText);
        if ($length < self::TAG_LENGTH) {
            throw new \LengthException("Invalid OCB cipher text.");
        }

        $tag = substr($cipherText, $length - self::TAG_LENGTH);
        $cipherText = substr($cipherText, 0, $length - self::TAG_LENGTH);

        $crypted = $this->crypt($this->decipher, $cipherText, $nonce, $aData);
        $length = strlen($crypted);
        // if (Tag[1..TAGLEN] == T)
        if (strcmp($tag, substr($crypted, $length - self::TAG_LENGTH)) === 0) {
            return substr($crypted, 0, $length - self::TAG_LENGTH);
        }
        throw new \RuntimeException("Authentication tag mismatch!");
    }

    /**
     * {@inheritdoc}
     */
    public function getNonce(string $iv, string $chunkIndex): string
    {
        return substr_replace($iv, substr($iv, 7) ^ $chunkIndex, 7);
    }

    /**
     * Encrypt/decrypt data.
     *
     * @param EcbCipher $cipher - Encryption/decryption block cipher function
     * @param string $text - The cleartext or ciphertext (without tag) input
     * @param string $nonce - The nonce (15 bytes)
     * @param string $aData - Associated data to sign
     * @return string The ciphertext or plaintext output, with tag appended in both cases.
     */
    private function crypt(
        EcbCipher $cipher,
        string $text,
        string $nonce,
        string $aData,
    ): string {
        $length = strlen($text);
        // Consider P as a sequence of 128-bit blocks
        $m = floor($length / self::BLOCK_LENGTH) | 0;

        // Key-dependent variables
        $this->extendKeyVariables($text, $aData);

        // Nonce-dependent and per-encryption variables
        //
        // Nonce = num2str(TAGLEN mod 128,7) || zeros(120-bitlen(N)) || 1 || N
        // Note: We assume here that tagLength mod 16 == 0.
        $paddedNonce = implode([
            substr(self::ZERO_BLOCK, 0, self::IV_LENGTH - strlen($nonce)),
            self::ONE_CHAR,
            $nonce,
        ]);
        // bottom = str2num(Nonce[123..128])
        $bottom = ord($paddedNonce[self::BLOCK_LENGTH - 1]) & 0x3f;
        // Ktop = ENCIPHER(K, Nonce[1..122] || zeros(6))
        $paddedNonce[self::BLOCK_LENGTH - 1] = chr(
            ord($paddedNonce[self::BLOCK_LENGTH - 1]) & 0xc0,
        );
        $kTop = $this->encipher->encryptBlock($paddedNonce);
        //  Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72])
        $stretched = implode([
            $kTop,
            self::xor(substr($kTop, 0, 8), substr($kTop, 1, 9)),
        ]);
        // Offset_0 = Stretch[1+bottom..128+bottom]
        $offset = substr(
            self::shiftRight(
                substr($stretched, 0 + ($bottom >> 3), 17 + ($bottom >> 3)),
                8 - ($bottom & 7),
            ),
            1,
        );
        // Checksum_0 = zeros(128)
        $checksum = self::ZERO_BLOCK;

        $ct = str_repeat(self::ZERO_CHAR, $length + self::TAG_LENGTH);

        // Process any whole blocks
        $i = 0;
        $pos = 0;
        for ($i = 0; $i < $m; $i++) {
            // Offset_i = Offset_{i-1} xor L_{ntz(i)}
            $offset = self::xor($offset, $this->mask[self::ntz($i + 1)]);
            // C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)
            // P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i)
            if ($cipher === $this->encipher) {
                $encrypted = self::xor(
                    $cipher->encryptBlock(self::xor($offset, $text)),
                    $offset,
                );
            } else {
                $encrypted = self::xor(
                    $cipher->decryptBlock(self::xor($offset, $text)),
                    $offset,
                );
            }
            $ct = substr_replace($ct, $encrypted, $pos, strlen($encrypted));
            // Checksum_i = Checksum_{i-1} xor P_i
            $checksum = self::xor(
                $checksum,
                $cipher === $this->encipher ? $text : substr($ct, $pos),
            );

            $text = substr($text, self::BLOCK_LENGTH);
            $pos += self::BLOCK_LENGTH;
        }

        // Process any final partial block and compute raw tag
        $length = strlen($text);
        if ($length) {
            // Offset_* = Offset_m xor L_*
            $offset = self::xor($offset, $this->mask[self::MASK_ASTERISK]);
            // Pad = ENCIPHER(K, Offset_*)
            $padding = $this->encipher->encryptBlock($offset);
            // C_* = P_* xor Pad[1..bitlen(P_*)]
            $paddedText = self::xor($text, $padding);
            $ct = substr_replace($ct, $paddedText, $pos, strlen($paddedText));

            // Checksum_* = Checksum_m xor (P_* || 1 || new Uint8Array(127-bitlen(P_*)))
            $input =
                $cipher === $this->encipher
                    ? $text
                    : substr($ct, $pos, strlen($ct) - self::TAG_LENGTH);
            $xorInput = substr_replace(
                self::ZERO_BLOCK,
                $input,
                0,
                strlen($input),
            );
            $xorInput[$length] = "\x80";
            $checksum = self::xor($checksum, $xorInput);
            $pos += $length;
        }
        // Tag = ENCIPHER(K, Checksum_* xor Offset_* xor L_$) xor HASH(K,A)
        $tag = self::xor(
            $this->encipher->encryptBlock(
                self::xor(
                    self::xor($checksum, $offset),
                    $this->mask[self::MASK_DOLLAR],
                ),
            ),
            self::hash($aData),
        );

        // Assemble ciphertext
        // C = C_1 || C_2 || ... || C_m || C_* || Tag[1..TAGLEN]
        return substr_replace($ct, $tag, $pos, strlen($tag));
    }

    private function extendKeyVariables(string $text, string $aData): void
    {
        $newMaxNtz =
            self::nbits(
                floor(max(strlen($text), strlen($aData)) / self::BLOCK_LENGTH) |
                    0,
            ) - 1;
        for ($i = $this->maxNtz + 1; $i <= $newMaxNtz; $i++) {
            $this->mask[$i] = self::double($this->mask[$i - 1]);
        }
        $this->maxNtz = $newMaxNtz;
    }

    private function hash(string $aData): string
    {
        $length = strlen($aData);
        if (!$length) {
            // Fast path
            return self::ZERO_BLOCK;
        }

        // Consider A as a sequence of 128-bit blocks
        $m = floor($length / self::BLOCK_LENGTH) | 0;
        $offset = $sum = self::ZERO_BLOCK;
        for ($i = 0; $i < $m; $i++) {
            $offset = self::xor($offset, $this->mask[self::ntz($i + 1)]);
            $sum = self::xor(
                $sum,
                $this->encipher->encryptBlock(self::xor($offset, $aData)),
            );
            $aData = substr($aData, self::BLOCK_LENGTH);
        }

        // Process any final partial block; compute final hash value
        $length = strlen($aData);
        if ($length) {
            $offset = self::xor($offset, $this->mask[self::MASK_ASTERISK]);

            $cipherInput = substr_replace(
                self::ZERO_BLOCK,
                $aData,
                0,
                strlen($aData),
            );
            $cipherInput[$length] = "\x80";
            $cipherInput = self::xor($cipherInput, $offset);

            $sum = self::xor($sum, $this->encipher->encryptBlock($cipherInput));
        }

        return $sum;
    }

    private static function ntz(int $n): int
    {
        $ntz = 0;
        for ($i = 1; ($n & $i) === 0; $i <<= 1) {
            $ntz++;
        }
        return $ntz;
    }

    private static function xor(string $block, string $val): string
    {
        return $block ^ $val;
    }

    /**
     * If S[1] == 0, then double(S) == (S[2..128] || 0);
     * otherwise, double(S) == (S[2..128] || 0) xor (zeros(120) || 10000111).
     *
     * @param string $data
     * @return string
     */
    private static function double(string $data): string
    {
        $doubleVar = str_repeat(self::ZERO_CHAR, strlen($data));
        $last = strlen($data) - 1;
        for ($i = 0; $i < $last; $i++) {
            $doubleVar[$i] = chr(
                (ord($data[$i]) << 1) ^ (ord($data[$i + 1]) >> 7),
            );
        }
        $doubleVar[$last] = chr(
            (ord($data[$last]) << 1) ^ ((ord($data[0]) >> 7) * 0x87),
        );
        return $doubleVar;
    }

    /**
     * Return bit length of the integer x
     *
     * @param int $x
     * @return int
     */
    private static function nbits(int $x): int
    {
        $r = 1;
        $t = $x >> 16;
        if ($t !== 0) {
            $x = $t;
            $r += 16;
        }
        $t = $x >> 8;
        if ($t !== 0) {
            $x = $t;
            $r += 8;
        }
        $t = $x >> 4;
        if ($t !== 0) {
            $x = $t;
            $r += 4;
        }
        $t = $x >> 2;
        if ($t !== 0) {
            $x = $t;
            $r += 2;
        }
        $t = $x >> 1;
        if ($t !== 0) {
            $x = $t;
            $r += 1;
        }
        return $r;
    }

    /**
     * Shift a data to the right by n bits
     *
     * @param string $data - The data to shift
     * @param int $bits - Amount of bits to shift (MUST be smaller than 8)
     * @return string
     */
    private static function shiftRight(string $data, int $bits): string
    {
        if ($bits) {
            for ($i = strlen($data) - 1; $i >= 0; $i--) {
                $data[$i] = chr(ord($data[$i]) >> $bits);
                if ($i > 0) {
                    $data[$i] = chr(
                        ord($data[$i]) | (ord($data[$i - 1]) << 8 - $bits),
                    );
                }
            }
        }
        return $data;
    }
}
