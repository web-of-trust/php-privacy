<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Common;

use OpenPGP\Enum\ArmorType;

/**
 * Armor class
 *
 * @package   OpenPGP
 * @category  Common
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
final class Armor
{
    const MESSAGE_BEGIN        = "-----BEGIN PGP MESSAGE-----\n";
    const SIGNED_MESSAGE_BEGIN = "-----BEGIN PGP SIGNED MESSAGE-----\n";
    const MESSAGE_END          = "-----END PGP MESSAGE-----\n";

    const MULTIPART_SECTION_MESSAGE_BEGIN = "-----BEGIN PGP MESSAGE, PART %u/%u-----\n";
    const MULTIPART_SECTION_MESSAGE_END   = "-----END PGP MESSAGE, PART %u/%u-----\n";

    const MULTIPART_LAST_MESSAGE_BEGIN = "-----BEGIN PGP MESSAGE, PART %u-----\n";
    const MULTIPART_LAST_MESSAGE_END   = "-----END PGP MESSAGE, PART %u-----\n";

    const PUBLIC_KEY_BLOCK_BEGIN = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n";
    const PUBLIC_KEY_BLOCK_END   = "-----END PGP PUBLIC KEY BLOCK-----\n";

    const PRIVATE_KEY_BLOCK_BEGIN = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n";
    const PRIVATE_KEY_BLOCK_END   = "-----END PGP PRIVATE KEY BLOCK-----\n";

    const SIGNATURE_BEGIN = "-----BEGIN PGP SIGNATURE-----\n";
    const SIGNATURE_END   = "-----END PGP SIGNATURE-----\n";

    const SPLIT_PATTERN      = '/^-----[^-]+-----$/';
    const EMPTY_LINE_PATTERN = '/(^[\r\n]*|[\r\n]+)[\s\t]*[\r\n]+/';
    const LIME_SPLIT_PATTERN = '/\r\n|\n|\r/';
    const HEADER_PATTERN     = '/^([^\s:]|[^\s:][^:]*[^\s:]): .+$/';
    const BEGIN_PATTERN      = '/^-----BEGIN PGP (MESSAGE, PART \d+\/\d+|MESSAGE, PART \d+|SIGNED MESSAGE|MESSAGE|PUBLIC KEY BLOCK|PRIVATE KEY BLOCK|SIGNATURE)-----$/';

    const EOL   = "\n";
    const CRLF  = "\r\n";
    const TRUNK = 76;

    /**
     * Constructor
     *
     * @param ArmorType $type
     * @param array $headers
     * @param string $data
     * @param string $text
     * @return self
     */
    public function __construct(
        private ArmorType $type,
        private array $headers = [],
        private string $data = '',
        private string $text = ''
    )
    {
    }

    /**
     * Gets armor type
     *
     * @return ArmorType
     */
    public function getType(): ArmorType
    {
        return $this->type;
    }

    /**
     * Gets armor headers
     *
     * @return array
     */
    public function getHeaders(): array
    {
        return $this->headers;
    }

    /**
     * Geta armor data
     *
     * @return string
     */
    public function getData(): string
    {
        return $this->data;
    }

    /**
     * Gets armor text
     *
     * @return string
     */
    public function getText(): string
    {
        return $this->text;
    }

    /**
     * Dearmor an OpenPGP armored message;
     * Verify the checksum and return the encoded bytes
     *
     * @param string $armoredText
     * @param bool $checksumRequired
     * @return self
     */
    public static function decode(string $armoredText, bool $checksumRequired = true): self
    {
        $textDone = false;
        $checksum = '';
        $type = null;

        $headers = [];
        $textLines = [];
        $dataLines = [];

        $lines = preg_split(self::LIME_SPLIT_PATTERN, $armoredText);
        foreach ($lines as $line) {
            if ($type === null && preg_match(self::SPLIT_PATTERN, $line)) {
                $type = self::parseType($line);
            }
            else {
                if (preg_match(self::HEADER_PATTERN, $line)) {
                    $headers[] = $line;
                }
                elseif (!$textDone && $type == ArmorType::SignedMessage) {
                    if (!preg_match(self::SPLIT_PATTERN, $line)) {
                        $textLines[] = preg_replace('/^- /', '', $line);
                    }
                    else {
                        $textDone = true;
                    }
                }
                elseif (!preg_match(self::SPLIT_PATTERN, $line)) {
                    if (preg_match(self::EMPTY_LINE_PATTERN, $line)) {
                        continue;
                    }
                    if (strpos($line, '=') === 0) {
                        $checksum = substr($line, 1);
                    }
                    else {
                        $dataLines[] = $line;
                    }
                }
            }
        }

        $data = base64_decode(implode($dataLines));
        if (($checksum != self::crc24Checksum($data)) && (!empty($checksum) || $checksumRequired)) {
            throw new \UnexpectedValueException(
                'Ascii armor integrity check failed'
            );
        }

        return new self(
            $type, $headers, $data, trim(implode(self::CRLF, $textLines))
        );
    }

    /**
     * Armor an OpenPGP binary packet block
     *
     * @param ArmorType $type
     * @param string $data
     * @param string $text
     * @param string $hashAlgo
     * @param int $partIndex
     * @param int $partTotal
     * @param string $customComment
     * @return string
     */
    public static function encode(
        ArmorType $type,
        string $data,
        string $text = '',
        string $hashAlgo = '',
        int $partIndex = 0,
        int $partTotal = 0,
        string $customComment = ''
    ): string
    {
        $result = match($type) {
            ArmorType::MultipartSection => [
                sprintf(self::MULTIPART_SECTION_MESSAGE_BEGIN, $partIndex, $partTotal),
                self::addHeader($customComment) . self::EOL,
                chunk_split(base64_encode($data), self::TRUNK, self::EOL) . self::EOL,
                '=' . self::crc24Checksum($data) . self::EOL,
                sprintf(self::MULTIPART_SECTION_MESSAGE_END, $partIndex, $partTotal),
            ],
            ArmorType::MultipartLast => [
                sprintf(self::MULTIPART_LAST_MESSAGE_BEGIN, $partIndex),
                self::addHeader($customComment) . self::EOL,
                chunk_split(base64_encode($data), self::TRUNK, self::EOL) . self::EOL,
                '=' . self::crc24Checksum($data) . self::EOL,
                sprintf(self::MULTIPART_LAST_MESSAGE_END, $partIndex),
            ],
            ArmorType::SignedMessage => [
                self::SIGNED_MESSAGE_BEGIN,
                "Hash: $hashAlgo" . self::EOL . self::EOL,
                str_replace('-', '- -', $text) . self::EOL,
                self::SIGNATURE_BEGIN,
                self::addHeader($customComment) . self::EOL,
                chunk_split(base64_encode($data), self::TRUNK, self::EOL) . self::EOL,
                '=' . self::crc24Checksum($data) . self::EOL,
                self::SIGNATURE_END,
            ],
            ArmorType::Message => [
                self::MESSAGE_BEGIN,
                self::addHeader($customComment) . self::EOL,
                chunk_split(base64_encode($data), self::TRUNK, self::EOL) . self::EOL,
                '=' . self::crc24Checksum($data) . self::EOL,
                self::MESSAGE_END,
            ],
            ArmorType::PublicKey => [
                self::PUBLIC_KEY_BLOCK_BEGIN,
                self::addHeader($customComment) . self::EOL,
                chunk_split(base64_encode($data), self::TRUNK, self::EOL) . self::EOL,
                '=' . self::crc24Checksum($data) . self::EOL,
                self::PUBLIC_KEY_BLOCK_END,
            ],
            ArmorType::PrivateKey => [
                self::PRIVATE_KEY_BLOCK_BEGIN,
                self::addHeader($customComment) . self::EOL,
                chunk_split(base64_encode($data), self::TRUNK, self::EOL) . self::EOL,
                '=' . self::crc24Checksum($data) . self::EOL,
                self::PRIVATE_KEY_BLOCK_END,
            ],
            ArmorType::Signature => [
                self::SIGNATURE_BEGIN,
                self::addHeader($customComment) . self::EOL,
                chunk_split(base64_encode($data), self::TRUNK, self::EOL) . self::EOL,
                '=' . self::crc24Checksum($data) . self::EOL,
                self::SIGNATURE_END,
            ],
        };
        return implode($result);
    }

    /**
     * Finds out which Ascii Armoring type is used.
     * 
     * @param string $armoredText
     * @return ArmorType
     */
    private static function parseType(string $armoredText): ArmorType
    {
        preg_match(self::BEGIN_PATTERN, $armoredText, $matches);
        if (empty($matches)) {
            throw new \InvalidArgumentException('Unknown ASCII armor type');
        }
        $type = match (1) {
            preg_match('/MESSAGE, PART \d+\/\d+/', $matches[0]) => ArmorType::MultipartSection,
            preg_match('/MESSAGE, PART \d+/', $matches[0]) => ArmorType::MultipartLast,
            preg_match('/SIGNED MESSAGE/', $matches[0]) => ArmorType::SignedMessage,
            preg_match('/MESSAGE/', $matches[0]) => ArmorType::Message,
            preg_match('/PUBLIC KEY BLOCK/', $matches[0]) => ArmorType::PublicKey,
            preg_match('/PRIVATE KEY BLOCK/', $matches[0]) => ArmorType::PrivateKey,
            preg_match('/SIGNATURE/', $matches[0]) => ArmorType::Signature,
        };
        return $type ?? ArmorType::MultipartSection;
    }

    /**
     * Add additional information to the armor of an OpenPGP binary packet block.
     * 
     * @param string $customComment
     * @return string
     */
    private static function addHeader(string $customComment = ''): string
    {
        $headers = [
            'Version: ' . Config::VERSION . self::EOL,
            'Comment: ' . Config::COMMENT . self::EOL,
        ];
        if (!empty($customComment)) {
            $headers[] = 'Comment: ' . $customComment . self::EOL;
        }
        return implode($headers);
    }

    /**
     * Calculates a checksum over the given data and returns it base64 encoded
     * 
     * @param string $data
     * @return string
     */
    private static function crc24Checksum(string $data): string
    {
        $crc = 0xb704ce;
        for ($i = 0; $i < strlen($data); $i++) {
            $crc ^= (ord($data[$i]) & 255) << 16;
            for ($j = 0; $j < 8; $j++) {
                $crc <<= 1;
                if ($crc & 0x1000000) {
                    $crc ^= 0x1864cfb;
                }
            }
        }
        return base64_encode(substr(pack('N', $crc & 0xffffff), 1));
    }
}
