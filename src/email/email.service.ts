import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import * as handlebars from 'handlebars';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class EmailService {
  private readonly transporter: nodemailer.Transporter;
  private readonly emailVerifyTemplate: HandlebarsTemplateDelegate;
  private readonly resetPasswordTemplate: HandlebarsTemplateDelegate;

  constructor() {
    // Initialize the transporter with your email configuration
    this.transporter = nodemailer.createTransport({
      host: process.env.NODEMAILER_HOST,
      port: parseInt(process.env.NODEMAILER_PORT!),
      auth: {
        user: process.env.NODEMAILER_USER,
        pass: process.env.NODEMAILER_PASS,
      },
    });

    // Get the path to the email-templates directory
    const templatesDir = path.join(
      __dirname,
      '../..',
      'assets',
      'email-templates',
    );

    // Read the Handlebars templates
    const emailVerifyTemplateSource = fs.readFileSync(
      path.join(templatesDir, 'email-verify.hbs'),
      'utf8',
    );
    const resetPasswordTemplateSource = fs.readFileSync(
      path.join(templatesDir, 'reset-password.hbs'),
      'utf8',
    );

    // Compile the templates
    this.emailVerifyTemplate = handlebars.compile(emailVerifyTemplateSource);
    this.resetPasswordTemplate = handlebars.compile(
      resetPasswordTemplateSource,
    );
  }

  private async sendEmail(
    to: string,
    subject: string,
    body: string,
  ): Promise<void> {
    try {
      const mailOptions: nodemailer.SendMailOptions = {
        from: process.env.FROM_EMAIL, // Replace with your email address
        to,
        subject,
        html: body,
      };

      await this.transporter.sendMail(mailOptions);
    } catch (error) {
      // Handle any errors that occur during email sending (e.g., log, throw, etc.)
      throw new Error('Failed to send email: ' + error.message);
    }
  }

  async sendVerificationEmail(
    to: string,
    verificationLink: string,
  ): Promise<void> {
    const subject = 'Email Verification';
    const body = this.emailVerifyTemplate({ verificationLink });
    await this.sendEmail(to, subject, body);
  }

  async sendResetPasswordEmail(to: string, resetLink: string): Promise<void> {
    const subject = 'Reset Password';
    const body = this.resetPasswordTemplate({ resetLink });
    await this.sendEmail(to, subject, body);
  }
}
