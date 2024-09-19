<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Common;

use phpseclib3\Common\Functions\Strings;
use OpenPGP\Enum\ArmorType;

/**
 * Armor class
 *
 * Class that represents an OpenPGP Base64 Conversions.
 * See RFC 9580, section 6.
 * 
 * @package  OpenPGP
 * @category Common
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
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

    const SPLIT_PATTERN  = '/^-----[^-]+-----$/';
    const HEADER_PATTERN = '/^([^\s:]|[^\s:][^:]*[^\s:]): .+$/';

    const TRUNK_SIZE = 76;

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
     * Get armor type
     *
     * @return ArmorType
     */
    public function getType(): ArmorType
    {
        return $this->type;
    }

    /**
     * Get armor headers
     *
     * @return array
     */
    public function getHeaders(): array
    {
        return $this->headers;
    }

    /**
     * Get armor data
     *
     * @return string
     */
    public function getData(): string
    {
        return $this->data;
    }

    /**
     * Get armor text
     *
     * @return string
     */
    public function getText(): string
    {
        return $this->text;
    }

    /**
     * Assert armor type
     *
     * @param ArmorType $type
     * @return self
     */
    public function assert(ArmorType $type): self
    {
        if ($this->type !== $type) {
            throw new \UnexpectedValueException(
                "Armored text not of {$type->name} type."
            );
        }
        return $this;
    }

    /**
     * Dearmor an OpenPGP armored message.
     * Verify the checksum and return the encoded bytes
     *
     * @param string $armoredText
     * @param bool $checksumRequired
     * @return self
     */
    public static function decode(
        string $armoredText, bool $checksumRequired = false
    ): self
    {
        $textDone = false;
        $checksum = '';
        $type = null;

        $headers = [];
        $textLines = [];
        $dataLines = [];

        $lines = preg_split(Helper::LINE_SPLIT_PATTERN, $armoredText);
        if (!empty($lines)) {
            foreach ($lines as $line) {
                /// Remove trailing whitespaces
                $line = rtrim($line, " \r\t");
                if ($type === null && preg_match(self::SPLIT_PATTERN, $line)) {
                    $type = ArmorType::fromBegin($line);
                }
                else {
                    if (preg_match(self::HEADER_PATTERN, $line)) {
                        $headers[] = $line;
                    }
                    elseif (!$textDone && $type === ArmorType::SignedMessage) {
                        if (!preg_match(self::SPLIT_PATTERN, $line)) {
                            $textLines[] = $line;
                        }
                        else {
                            $textDone = true;
                            /// Remove first empty line (not included in the message digest)
                            if (isset($textLines[0]) && empty($textLines[0])) {
                                unset($textLines[0]);
                            }
                        }
                    }
                    elseif (!preg_match(self::SPLIT_PATTERN, $line)) {
                        if (preg_match(Helper::EMPTY_LINE_PATTERN, $line)) {
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
        }

        $data = Strings::base64_decode(implode($dataLines));
        if (strcmp($checksum, self::crc24Checksum($data)) !== 0 &&
           (!empty($checksum) || $checksumRequired))
        {
            throw new \RuntimeException(
                'Ascii armor integrity check failed!'
            );
        }

        return new self(
            $type ?? ArmorType::Message,
            $headers,
            $data,
            preg_replace(
                '/^- /m', '', implode(Helper::CRLF, $textLines)
            ), // Reverse dash-escaped text
        );
    }

    /**
     * Armor an OpenPGP binary packet block
     *
     * @param ArmorType $type
     * @param string $data
     * @param string $text
     * @param array $hashAlgos
     * @param int $partIndex
     * @param int $partTotal
     * @param string $customComment
     * @return string
     */
    public static function encode(
        ArmorType $type,
        string $data,
        string $text = '',
        array $hashAlgos = [],
        int $partIndex = 0,
        int $partTotal = 0,
        string $customComment = ''
    ): string
    {
        $result = match($type) {
            ArmorType::MultipartSection => [
                sprintf(self::MULTIPART_SECTION_MESSAGE_BEGIN, $partIndex, $partTotal),
                self::addHeader($customComment) . Helper::EOL,
                chunk_split(Strings::base64_encode($data), self::TRUNK_SIZE, Helper::EOL),
                '=' . self::crc24Checksum($data) . Helper::EOL,
                sprintf(self::MULTIPART_SECTION_MESSAGE_END, $partIndex, $partTotal),
            ],
            ArmorType::MultipartLast => [
                sprintf(self::MULTIPART_LAST_MESSAGE_BEGIN, $partIndex),
                self::addHeader($customComment) . Helper::EOL,
                chunk_split(Strings::base64_encode($data), self::TRUNK_SIZE, Helper::EOL),
                '=' . self::crc24Checksum($data) . Helper::EOL,
                sprintf(self::MULTIPART_LAST_MESSAGE_END, $partIndex),
            ],
            ArmorType::SignedMessage => [
                self::SIGNED_MESSAGE_BEGIN,
                !empty($hashAlgos) ? implode(
                    Helper::EOL,
                    array_map(static fn ($hashAlgo) => "Hash: $hashAlgo", $hashAlgos)
                ) . Helper::EOL . Helper::EOL : Helper::EOL,
                preg_replace('/^- /m', '- -', $text) . Helper::EOL, // Dash-escape text
                self::SIGNATURE_BEGIN,
                self::addHeader($customComment) . Helper::EOL,
                chunk_split(Strings::base64_encode($data), self::TRUNK_SIZE, Helper::EOL),
                '=' . self::crc24Checksum($data) . Helper::EOL,
                self::SIGNATURE_END,
            ],
            ArmorType::Message => [
                self::MESSAGE_BEGIN,
                self::addHeader($customComment) . Helper::EOL,
                chunk_split(Strings::base64_encode($data), self::TRUNK_SIZE, Helper::EOL),
                '=' . self::crc24Checksum($data) . Helper::EOL,
                self::MESSAGE_END,
            ],
            ArmorType::PublicKey => [
                self::PUBLIC_KEY_BLOCK_BEGIN,
                self::addHeader($customComment) . Helper::EOL,
                chunk_split(Strings::base64_encode($data), self::TRUNK_SIZE, Helper::EOL),
                '=' . self::crc24Checksum($data) . Helper::EOL,
                self::PUBLIC_KEY_BLOCK_END,
            ],
            ArmorType::PrivateKey => [
                self::PRIVATE_KEY_BLOCK_BEGIN,
                self::addHeader($customComment) . Helper::EOL,
                chunk_split(Strings::base64_encode($data), self::TRUNK_SIZE, Helper::EOL),
                '=' . self::crc24Checksum($data) . Helper::EOL,
                self::PRIVATE_KEY_BLOCK_END,
            ],
            ArmorType::Signature => [
                self::SIGNATURE_BEGIN,
                self::addHeader($customComment) . Helper::EOL,
                chunk_split(Strings::base64_encode($data), self::TRUNK_SIZE, Helper::EOL),
                '=' . self::crc24Checksum($data) . Helper::EOL,
                self::SIGNATURE_END,
            ],
        };
        return implode($result);
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
            'Version: ' . Config::VERSION . Helper::EOL,
            'Comment: ' . Config::COMMENT . Helper::EOL,
        ];
        if (!empty($customComment)) {
            $headers[] = 'Comment: ' . $customComment . Helper::EOL;
        }
        return implode($headers);
    }

    /**
     * Calculate a checksum over the given data and returns it base64 encoded
     *
     * @param string $data
     * @return string
     */
    private static function crc24Checksum(string $data): string
    {
        $crc = 0xb704ce;
        for ($i = 0, $len = strlen($data); $i < $len; $i++) {
            $crc ^= (ord($data[$i]) & 255) << 16;
            for ($j = 0; $j < 8; $j++) {
                $crc <<= 1;
                if ($crc & 0x1000000) {
                    $crc ^= 0x1864cfb;
                }
            }
        }
        return Strings::base64_encode(
            substr(pack('N', $crc & 0xffffff), 1)
        );
    }
}
