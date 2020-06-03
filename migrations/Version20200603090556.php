<?php

declare(strict_types=1);

namespace App\migrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20200603090556 extends AbstractMigration
{
    public function up(Schema $schema): void
    {
        $sql = "CREATE TABLE user(
                id int UNSIGNED auto_increment not null,
                email VARCHAR(255) not null ,
                password varchar(255) not null ,
                name varchar(255) not null,
                primary key (id))";
        $this->addSql($sql);
    }

    public function down(Schema $schema): void
    {
        $this->addSql('DROP TABLE user');
    }
}
