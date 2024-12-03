import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';
export class RegisterUserDto {
  @ApiProperty({ description: "The user's username" })
  @IsNotEmpty()
  @IsString()
  username: string;
  @ApiProperty({ description: "The user's email address" })
  @IsNotEmpty()
  @IsEmail()
  email: string;
  @ApiProperty({ description: "The user's password" })
  @IsNotEmpty()
  @Length(6, 20)
  password: string;
}
