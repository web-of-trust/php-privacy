<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Enum\PacketTag;
use OpenPGP\Type\UserIDPacketInterface;

/**
 * UserID packet class
 * 
 * Implementation of the User ID packet (Tag 13)
 * A User ID packet consists of UTF-8 text that is intended to represent
 * the name and email address of the key holder.
 * By convention, it includes an RFC2822 mail name-addr,
 * but there are no restrictions on its content.
 * The packet length in the header specifies the length of the User ID.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class UserID extends AbstractPacket implements UserIDPacketInterface
{
    private string $name;

    private string $email;

    private string $comment;

    /**
     * Constructor
     *
     * @param string $userID
     * @return self
     */
    public function __construct(private readonly string $userID)
    {
        parent::__construct(PacketTag::UserID);

        if (preg_match('/^([^\(]+)\(([^\)]+)\)\s+<([^>]+)>$/', $userID, $matches)) {
            // User IDs of the form: "name (comment) <email>"
            $this->name    = trim($matches[1]);
            $this->email   = trim($matches[3]);
            $this->comment = trim($matches[2]);
        }
        elseif (preg_match('/^([^<]+)\s+<([^>]+)>$/', $this->userID, $matches)) {
            // User IDs of the form: "name <email>"
            $this->name  = trim($matches[1]);
            $this->email = trim($matches[2]);
            $this->comment = '';
        }
        elseif (preg_match('/^([^<]+)$/', $this->userID, $matches)) {
            // User IDs of the form: "name"
            $this->name = trim($matches[1]);
            $this->email = '';
            $this->comment = '';
        }
        elseif (preg_match('/^<([^>]+)>$/', $this->userID, $matches)) {
            // User IDs of the form: "<email>"
            $this->name = '';
            $this->email = trim($matches[2]);
            $this->comment = '';
        }
        else {
            $this->name = '';
            $this->email = '';
            $this->comment = '';
        }
    }

    /**
     * Reads user ID from byte string
     *
     * @param string $bytes
     * @return self
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
            pack('N', strlen($this->userID)),
            $this->userID,
        ]);
    }

    /**
     * Gets user ID
     *
     * @return string
     */
    public function getUserID(): string
    {
        return $this->userID;
    }

    /**
     * Gets name
     *
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Gets email
     *
     * @return string
     */
    public function getEmail(): string
    {
        return $this->email;
    }

    /**
     * Gets comment
     *
     * @return string
     */
    public function getComment(): string
    {
        return $this->comment;
    }
}
