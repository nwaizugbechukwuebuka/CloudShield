"""
Email Service for User Communications
"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import List, Optional, Dict
import asyncio
from datetime import datetime
import jinja2
from pathlib import Path

from ..utils.config import settings
from ..utils.logger import get_logger

logger = get_logger(__name__)


class EmailService:
    """Comprehensive email service for user communications"""
    
    def __init__(self):
        self.smtp_server = settings.SMTP_HOST
        self.smtp_port = settings.SMTP_PORT
        self.smtp_username = settings.SMTP_USERNAME
        self.smtp_password = settings.SMTP_PASSWORD
        self.use_tls = settings.SMTP_USE_TLS
        self.from_email = settings.FROM_EMAIL
        self.from_name = settings.FROM_NAME or "CloudShield Security"
        
        # Setup Jinja2 template environment
        template_dir = Path(__file__).parent.parent.parent / "templates" / "emails"
        self.template_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
    
    async def send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
        attachments: Optional[List[Dict]] = None
    ) -> bool:
        """Send an email with optional attachments"""
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{self.from_name} <{self.from_email}>"
            msg['To'] = to_email
            msg['Subject'] = subject
            
            # Add text version if provided
            if text_content:
                msg.attach(MIMEText(text_content, 'plain'))
            
            # Add HTML content
            msg.attach(MIMEText(html_content, 'html'))
            
            # Add attachments if provided
            if attachments:
                for attachment in attachments:
                    self._add_attachment(msg, attachment)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                
                if self.smtp_username and self.smtp_password:
                    server.login(self.smtp_username, self.smtp_password)
                
                server.send_message(msg)
            
            logger.info(f"Email sent successfully to {to_email}: {subject}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {str(e)}")
            return False
    
    def _add_attachment(self, msg: MIMEMultipart, attachment: Dict):
        """Add attachment to email message"""
        
        try:
            with open(attachment['path'], 'rb') as f:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header(
                    'Content-Disposition',
                    f'attachment; filename= {attachment["filename"]}'
                )
                msg.attach(part)
        except Exception as e:
            logger.error(f"Failed to add attachment: {str(e)}")
    
    async def send_welcome_email(self, user_email: str, user_name: str) -> bool:
        """Send welcome email to new user"""
        
        try:
            template = self.template_env.get_template('welcome.html')
            html_content = template.render(
                user_name=user_name,
                app_name=settings.APP_NAME,
                login_url=f"{settings.FRONTEND_URL}/login",
                support_email=settings.SUPPORT_EMAIL or self.from_email
            )
            
            subject = f"Welcome to {settings.APP_NAME}!"
            
            return await self.send_email(user_email, subject, html_content)
            
        except Exception as e:
            logger.error(f"Failed to send welcome email: {str(e)}")
            return False
    
    async def send_password_reset_email(
        self, 
        user_email: str, 
        user_name: str, 
        reset_token: str
    ) -> bool:
        """Send password reset email"""
        
        try:
            template = self.template_env.get_template('password_reset.html')
            reset_url = f"{settings.FRONTEND_URL}/reset-password?token={reset_token}"
            
            html_content = template.render(
                user_name=user_name,
                reset_url=reset_url,
                app_name=settings.APP_NAME,
                expiry_hours=1,
                support_email=settings.SUPPORT_EMAIL or self.from_email
            )
            
            subject = f"Password Reset - {settings.APP_NAME}"
            
            return await self.send_email(user_email, subject, html_content)
            
        except Exception as e:
            logger.error(f"Failed to send password reset email: {str(e)}")
            return False
    
    async def send_verification_email(
        self, 
        user_email: str, 
        user_name: str, 
        verification_token: str
    ) -> bool:
        """Send email verification email"""
        
        try:
            template = self.template_env.get_template('email_verification.html')
            verify_url = f"{settings.FRONTEND_URL}/verify-email?token={verification_token}"
            
            html_content = template.render(
                user_name=user_name,
                verify_url=verify_url,
                app_name=settings.APP_NAME,
                support_email=settings.SUPPORT_EMAIL or self.from_email
            )
            
            subject = f"Verify Your Email - {settings.APP_NAME}"
            
            return await self.send_email(user_email, subject, html_content)
            
        except Exception as e:
            logger.error(f"Failed to send verification email: {str(e)}")
            return False
    
    async def send_security_alert_email(
        self,
        user_email: str,
        user_name: str,
        alert_type: str,
        alert_details: Dict
    ) -> bool:
        """Send security alert notification"""
        
        try:
            template = self.template_env.get_template('security_alert.html')
            
            html_content = template.render(
                user_name=user_name,
                alert_type=alert_type,
                alert_details=alert_details,
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
                app_name=settings.APP_NAME,
                dashboard_url=f"{settings.FRONTEND_URL}/dashboard"
            )
            
            subject = f"Security Alert - {alert_type} - {settings.APP_NAME}"
            
            return await self.send_email(user_email, subject, html_content)
            
        except Exception as e:
            logger.error(f"Failed to send security alert email: {str(e)}")
            return False
    
    async def send_scan_completion_email(
        self,
        user_email: str,
        user_name: str,
        scan_results: Dict
    ) -> bool:
        """Send scan completion notification"""
        
        try:
            template = self.template_env.get_template('scan_completion.html')
            
            html_content = template.render(
                user_name=user_name,
                scan_results=scan_results,
                app_name=settings.APP_NAME,
                dashboard_url=f"{settings.FRONTEND_URL}/dashboard",
                findings_url=f"{settings.FRONTEND_URL}/findings"
            )
            
            subject = f"Scan Complete - {scan_results['platform']} - {settings.APP_NAME}"
            
            return await self.send_email(user_email, subject, html_content)
            
        except Exception as e:
            logger.error(f"Failed to send scan completion email: {str(e)}")
            return False
    
    async def send_weekly_summary_email(
        self,
        user_email: str,
        user_name: str,
        summary_data: Dict
    ) -> bool:
        """Send weekly security summary"""
        
        try:
            template = self.template_env.get_template('weekly_summary.html')
            
            html_content = template.render(
                user_name=user_name,
                summary_data=summary_data,
                app_name=settings.APP_NAME,
                dashboard_url=f"{settings.FRONTEND_URL}/dashboard"
            )
            
            subject = f"Weekly Security Summary - {settings.APP_NAME}"
            
            return await self.send_email(user_email, subject, html_content)
            
        except Exception as e:
            logger.error(f"Failed to send weekly summary email: {str(e)}")
            return False


# Global email service instance
email_service = EmailService()


# Convenience functions for use in routes
async def send_welcome_email(user_email: str, user_name: str) -> bool:
    """Send welcome email - convenience function"""
    return await email_service.send_welcome_email(user_email, user_name)


async def send_password_reset_email(
    user_email: str, 
    user_name: str, 
    reset_token: str
) -> bool:
    """Send password reset email - convenience function"""
    return await email_service.send_password_reset_email(
        user_email, user_name, reset_token
    )


async def send_verification_email(
    user_email: str, 
    user_name: str, 
    verification_token: str
) -> bool:
    """Send verification email - convenience function"""
    return await email_service.send_verification_email(
        user_email, user_name, verification_token
    )


async def send_security_alert_email(
    user_email: str,
    user_name: str,
    alert_type: str,
    alert_details: Dict
) -> bool:
    """Send security alert email - convenience function"""
    return await email_service.send_security_alert_email(
        user_email, user_name, alert_type, alert_details
    )


async def send_scan_completion_email(
    user_email: str,
    user_name: str,
    scan_results: Dict
) -> bool:
    """Send scan completion email - convenience function"""
    return await email_service.send_scan_completion_email(
        user_email, user_name, scan_results
    )


async def send_weekly_summary_email(
    user_email: str,
    user_name: str,
    summary_data: Dict
) -> bool:
    """Send weekly summary email - convenience function"""
    return await email_service.send_weekly_summary_email(
        user_email, user_name, summary_data
    )