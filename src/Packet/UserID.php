<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Enum\PacketTag;
use OpenPGP\Type\UserIDPacketInterface;

/**
 * User ID packet class
 *
 * Implementation of the User ID packet (Tag 13)
 * A User ID packet consists of UTF-8 text that is intended to represent
 * the name and email address of the key holder.
 * By convention, it includes an RFC2822 mail name-addr,
 * but there are no restrictions on its content.
 * The packet length in the header specifies the length of the User ID.
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class UserID extends AbstractPacket implements UserIDPacketInterface
{
    private readonly string $name;

    private readonly string $email;

    private readonly string $comment;

    /**
     * Constructor
     *
     * @param string $userID
     * @return self
     */
    public function __construct(private readonly string $userID)
    {
        parent::__construct(PacketTag::UserID);
        $this->name = $this->extractName();
        $this->email = $this->extractEmail();
        $this->comment = $this->extractComment();
    }

    /**
     * {@inheritdoc}
     */
    public static function fromBytes(string $bytes): self
    {
        return new self($bytes);
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return $this->userID;
    }

    /**
     * {@inheritdoc}
     */
    public function getSignBytes(): string
    {
        return implode([
            "\xb4",
            pack("N", strlen($this->userID)),
            $this->userID,
        ]);
    }

    /**
     * Get user ID
     *
     * @return string
     */
    public function getUserID(): string
    {
        return $this->userID;
    }

    /**
     * Get name
     *
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Get email
     *
     * @return string
     */
    public function getEmail(): string
    {
        return $this->email;
    }

    /**
     * Get comment
     *
     * @return string
     */
    public function getComment(): string
    {
        return $this->comment;
    }

    private function extractName(): string
    {
        $nameChars = [];
        $chars = str_split($this->userID);
        foreach ($chars as $char) {
            if ($char === "(" || $char === "<") {
                break;
            }
            $nameChars[] = $char;
        }
        return trim(implode($nameChars));
    }

    private function extractEmail(): string
    {
        if (
            preg_match("/[\w\.-]+@[\w\.-]+\.\w{2,4}/", $this->userID, $matches)
        ) {
            return $matches[0];
        }
        return "";
    }

    private function extractComment(): string
    {
        if (
            str_contains($this->userID, "(") &&
            str_contains($this->userID, ")")
        ) {
            $start = (int) strpos($this->userID, "(") + 1;
            $end = (int) strpos($this->userID, ")");
            return substr($this->userID, $start, $end - $start);
        }
        return "";
    }
}
