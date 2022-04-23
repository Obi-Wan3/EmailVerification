"""
MIT License

Copyright (c) 2021-present Obi-Wan3
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import asyncio
import base64
import functools
import json
import random
import re
import string
import typing
from collections import defaultdict
from copy import copy
from datetime import datetime, timezone
from email.mime.text import MIMEText

import discord
from redbot.core import commands, Config
from redbot.core.utils.chat_formatting import humanize_list, humanize_timedelta
from redbot.core.utils.predicates import MessagePredicate

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

DOMAIN_REGEX: re = re.compile(r"(\*\.)?[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+")
EMAIL_REGEX: re = re.compile(r"(?P<username>([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+)@(?P<domain>[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+)")

API_SCOPES: list = ["https://www.googleapis.com/auth/gmail.send"]
API_SETUP_INSTRUCTIONS: str = "https://gist.github.com/Obi-Wan3/a4a1579b00f53e0266b297bdbbb79732"
API_REDIRECT: str = "urn:ietf:wg:oauth:2.0:oob"

DEFAULT_SUBJECT: str = "Verify Your Email in {server}"
DEFAULT_CONTENT: str = "{user}, here is your verification code: {code}"

DM_ERROR: str = "I cannot DM you! Please make sure you have DMs enabled."
INVALID_DOMAIN: str = "Your email domain is not allowed!"


class EmailVerification(commands.Cog):
    """
    Email Verification

    Allow users to verify their email address via a command and/or reaction, with customizable options.
    """

    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=14000605, force_registration=True)

        default_global = {
            "oauth": ""
        }
        default_guild = {
            "credentials": "",
            "domains": {
                "allowed": [],
                "blocked": []
            },
            "reaction": {
                "channel": None,
                "message": None,
                "emoji": None
            },
            "roles": {
                "allowed": [],
                "blocked": [],
                "add": {},
                "remove": {}
            },
            "templates": {
                "subject": "",
                "content": ""
            },
            "timeout": 5,
            "domain_error": "",
            "log_channel": None,
        }
        self.config.register_global(**default_global)
        self.config.register_guild(**default_guild)

        self.last_dm: defaultdict = defaultdict(lambda: {})
        self.last_run: defaultdict = defaultdict(lambda: {})
        self.reaction_cache: defaultdict = defaultdict(lambda: {})

    async def _run_async(self, function, **kwargs):
        return await self.bot.loop.run_in_executor(None, functools.partial(function, **kwargs))

    @staticmethod
    async def _tick(message: discord.Message):
        try:
            return await message.add_reaction("\N{WHITE HEAVY CHECK MARK}")
        except discord.HTTPException:
            return

    @staticmethod
    async def _maybe_x(ctx: commands.Context, from_command: bool):
        if from_command:
            try:
                return await ctx.message.add_reaction("\N{CROSS MARK}")
            except discord.HTTPException:
                return

    @staticmethod
    async def _maybe_dm(message: str, ctx: commands.Context, from_command: bool) -> bool:
        try:
            await ctx.author.send(message)
        except discord.HTTPException:
            if from_command:
                await ctx.send(DM_ERROR)
            return False
        return True

    # Check if a domain is in a list
    @staticmethod
    async def _check_domains(to_check: str, domains: list) -> bool:
        return any([
            to_check.endswith(d[2:])
            if d.startswith("*.")
            else to_check == d
            for d in domains
        ])

    # Fill in email template
    @staticmethod
    async def _fill_template(template: str, user: discord.User, guild: discord.Guild, email: str, code: str):
        return template.replace(
            "{code}", code
        ).replace(
            "{email}", email
        ).replace(
            "{server}", guild.name
        ).replace(
            "{user}", f"{user.name}#{user.discriminator}"
        )

    # Get Credentials object of guild
    async def _get_guild_credentials(self, credential_string: str) -> typing.Optional[Credentials]:

        # Fetch json string from config
        if not credential_string:
            return

        # Create Credentials object from json string
        try:
            credentials: Credentials = await self._run_async(Credentials.from_authorized_user_info, info=json.loads(credential_string))
        except (ValueError, TypeError):
            return

        # Refresh Credentials if expired
        if credentials.expired:
            try:
                await self._run_async(credentials.refresh, request=Request())
            except Exception:
                return

        # Check credentials validity
        if not credentials or not credentials.valid:
            return

        return credentials

    # Send an email via the Gmail API
    async def _send_email(self, credentials: Credentials, email: str, subject: str, content: str) -> bool:

        # Construct Gmail resource to interact with API
        service = await self._run_async(build, serviceName='gmail', version='v1', credentials=credentials)

        # Create message object
        message = MIMEText(content)
        message['to'] = email
        message['subject'] = subject
        message = {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}

        # Send email in executor
        try:
            await self._run_async(service.users().messages().send(userId='me', body=message).execute)
        except Exception:
            return False

        return True

    # Verify an email
    async def _verification(self, ctx: commands.Context, from_command: bool):

        # Cooldown of 5min
        now: datetime = datetime.now(tz=timezone.utc)
        if last_run := self.last_run[ctx.guild.id].get(ctx.author.id):
            if (seconds := (now - datetime.utcfromtimestamp(last_run).replace(tzinfo=timezone.utc)).total_seconds()) < 300:
                if (last_run := self.last_dm[ctx.guild.id].get(ctx.author.id)) and ((now - datetime.utcfromtimestamp(last_run).replace(tzinfo=timezone.utc)).total_seconds() > 30):
                    self.last_dm[ctx.guild.id][ctx.author.id] = now.timestamp()
                    await self._maybe_dm(
                        message=f"Please wait {humanize_timedelta(seconds=(300 - seconds))} before trying email verification again.",
                        ctx=ctx,
                        from_command=from_command
                    )
                return await self._maybe_x(ctx, from_command)
        self.last_dm[ctx.guild.id][ctx.author.id] = now.timestamp()
        self.last_run[ctx.guild.id][ctx.author.id] = now.timestamp()

        # Fetch config
        guild_config: dict = await self.config.guild(ctx.guild).all()

        # Check user roles against verification role allow/blocklists
        if (
                (guild_config["roles"]["allowed"] and not any([r.id in guild_config["roles"]["allowed"] for r in ctx.author.roles])) or
                (guild_config["roles"]["blocked"] and any([r.id in guild_config["roles"]["blocked"] for r in ctx.author.roles]))
        ):
            await self._maybe_x(ctx, from_command)
            return await self._maybe_dm(
                message="You are not allowed to run this command!",
                ctx=ctx,
                from_command=from_command
            )

        # Check Credentials
        if not (credentials := await self._get_guild_credentials(guild_config["credentials"])):
            await self._maybe_x(ctx, from_command)
            return await self._maybe_dm(
                message="EmailVerification has not been set up for this server yet!",
                ctx=ctx,
                from_command=from_command
            )

        # Prompt for email
        if not await self._maybe_dm(
            message=f"Please enter your email address below for verification in {ctx.guild.name}.",
            ctx=ctx,
            from_command=from_command
        ):
            return await self._maybe_x(ctx, from_command)

        # Add tick reaction to original message
        if from_command:
            await ctx.tick()

        # MessagePredicate for ctx.author's DMs
        dm_predicate: MessagePredicate = MessagePredicate.same_context(channel=ctx.author.dm_channel, user=ctx.author)

        # Wait for user to enter email
        try:
            msg = await self.bot.wait_for("message", check=dm_predicate, timeout=180)
        except asyncio.TimeoutError:
            return await ctx.author.send("Error: operation timed out. Please try again.")

        # Validate email address format
        email: str = msg.content.lower()
        if not (email_match := EMAIL_REGEX.fullmatch(email)):
            return await ctx.author.send("Error: invalid email address. Please try again.")

        # Validate email domain against allow/blocklists
        email_domain: str = email_match.groupdict()["domain"]
        if (
                (guild_config["domains"]["allowed"] and not await self._check_domains(email_domain, guild_config["domains"]["allowed"])) or
                (guild_config["domains"]["blocked"] and await self._check_domains(email_domain, guild_config["domains"]["blocked"]))
        ):
            return await ctx.author.send(guild_config["domain_error"] or INVALID_DOMAIN)

        # User email input feedback
        await self._tick(msg)

        # Generate user verification code and store in cache
        user_code: str = "".join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=10))

        # Send email
        if not await self._send_email(
                credentials,
                email=email,
                subject=await self._fill_template(guild_config["templates"]["subject"] or DEFAULT_SUBJECT, ctx.author, ctx.guild, email, user_code),
                content=await self._fill_template(guild_config["templates"]["content"] or DEFAULT_CONTENT, ctx.author, ctx.guild, email, user_code)
        ):
            return await ctx.author.send("There was an error sending the verification code. Please contact the server and/or bot owner to make sure all necessary settings are configured and up to date.")
        await ctx.author.send(f"Please enter the verification code that was just emailed to you (times out in {guild_config['timeout']} minutes).")

        # Wait for user to return verification code
        try:
            msg = await self.bot.wait_for("message", check=dm_predicate, timeout=guild_config["timeout"]*60)
        except asyncio.TimeoutError:
            return await ctx.author.send("Error: operation timed out. Please try again.")

        # Check returned code
        if msg.content != user_code:
            return await ctx.author.send("Error: incorrect verification code. Please try again.")

        # User code input feedback
        await self._tick(msg)

        # Send log message
        if guild_config["log_channel"] and (channel := ctx.guild.get_channel(guild_config["log_channel"])) and channel.permissions_for(ctx.guild.me).send_messages and channel.permissions_for(ctx.guild.me).embed_links:
            await channel.send(embed=discord.Embed(
                title=f"Email Verified",
                description=f"{ctx.author.mention} ({ctx.author.id}): {email}",
                color=await ctx.embed_color()
            ))

        # Check guild permissions
        if ctx.guild.me.guild_permissions.manage_roles:
            user_roles: list = [r.id for r in ctx.author.roles]

            # Add roles
            for domain, roles in guild_config["roles"]["add"].items():
                if domain == "all" or await self._check_domains(email_domain, [domain]):
                    roles_to_add: list = [
                        role for rid in roles
                        if (role := ctx.guild.get_role(rid)) and rid not in user_roles and role < ctx.guild.me.top_role
                    ]
                    await ctx.author.add_roles(*roles_to_add, reason=f"EmailVerification: user verified {email}")

            # Remove roles
            for domain, roles in guild_config["roles"]["remove"].items():
                if domain == "all" or await self._check_domains(email_domain, [domain]):
                    roles_to_remove: list = [
                        role for rid in roles
                        if (role := ctx.guild.get_role(rid)) and rid in user_roles and role < ctx.guild.me.top_role
                    ]
                    await ctx.author.remove_roles(*roles_to_remove, reason=f"EmailVerification: user verified {email}")

        else:
            await ctx.author.send("I was unable to add/remove any roles due to a lack of permissions.")

        # Verify user
        return await ctx.author.send(f"Verification for `{email}` was successfully completed!")

    @commands.Cog.listener("on_raw_reaction_add")
    async def _reaction_listener(self, payload: discord.RawReactionActionEvent) -> None:

        # Check guild
        guild = self.bot.get_guild(payload.guild_id)
        if not guild or await self.bot.cog_disabled_in_guild(self, guild):
            return

        # Get emoji payload
        emoji = getattr(payload.emoji, "id", None) or str(payload.emoji)

        # Update cache if empty
        if not self.reaction_cache[payload.guild_id]:
            guild_settings = await self.config.guild(guild).reaction()
            self.reaction_cache[payload.guild_id] = {
                "channel": guild_settings["channel"],
                "message": guild_settings["message"],
                "emoji": guild_settings["emoji"]
            }

        # Check emoji and invoke [p]verify
        if (
                self.reaction_cache[payload.guild_id]["channel"] == payload.channel_id and
                self.reaction_cache[payload.guild_id]["message"] == payload.message_id and
                self.reaction_cache[payload.guild_id]["emoji"] == emoji
        ):
            msg_copy = copy(await guild.get_channel(payload.channel_id).fetch_message(payload.message_id))
            msg_copy.author = guild.get_member(payload.user_id)
            ctx = await self.bot.get_context(msg_copy)
            await self._verification(ctx, False)

    @commands.guild_only()
    @commands.command(name="verify")
    async def _verify(self, ctx: commands.Context):
        """Confirm your email through a verification code!"""
        return await self._verification(ctx, True)

    @commands.is_owner()
    @commands.command(name="gmailapisetup")
    async def _gmail_api_setup(self, ctx: commands.Context, remove: bool = False):
        """Set up the Gmail API for EmailVerification."""

        # Clear client config
        if remove:
            await self.config.oauth.clear()
            return await ctx.send("The Gmail API client configuration has been cleared.")

        # Send setup instructions
        if not ctx.message.attachments or not ctx.message.attachments[0].filename.endswith(".json"):
            return await ctx.send(f"Please follow the Gmail API setup instructions: {API_SETUP_INSTRUCTIONS}")

        # Load credentials from json file
        client_config = json.loads((await ctx.message.attachments[0].read()).decode('utf-8'))

        # Check config format
        try:
            await self._run_async(
                Flow.from_client_config,
                client_config=client_config,
                scopes=API_SCOPES,
                redirect_uri=API_REDIRECT
            )
        except ValueError:
            return await ctx.send("Error: invalid client configuration.")

        # Save to config
        await self.config.oauth.set(json.dumps(client_config))

        return await ctx.send("The Gmail API has been successfully configured!")

    @commands.guild_only()
    @commands.admin_or_permissions(administrator=True)
    @commands.group(name="emailverification")
    async def _email_verification(self, ctx: commands.Context):
        """EmailVerification Settings"""

    @commands.guildowner()
    @commands.bot_has_permissions(embed_links=True)
    @_email_verification.command(name="authorize")
    async def _authorize(self, ctx: commands.Context, remove: bool = False):
        """
        Authorize a Gmail account for sending emails via EmailVerification.

        Run `[p]emailverification authorize true` to remove the authorization information.
        """

        # Clear authorized account
        if remove:
            await self.config.guild(ctx.guild).credentials.clear()
            return await ctx.send("The connected Gmail account has been removed.")

        # Read in client config
        config: dict = json.loads(await self.config.oauth())
        if not config:
            return await ctx.send("The Gmail API has not yet been configured!")

        flow: Flow = await self._run_async(
            Flow.from_client_config,
            client_config=config,
            scopes=API_SCOPES,
            redirect_uri=API_REDIRECT
        )

        # Send authorization url
        await ctx.send(embed=discord.Embed(
            title="Authorize Your Account",
            url=flow.authorization_url()[0],
            description="**Click on the link above and follow the prompts** to authorize me to send verification emails via a Gmail account. This provides me **\"Send Email\" access in whichever account is used for authorization** (the email address will show up as the \"sender\" in verification emails to users). __**Send here the code you receive at the end of that authorization process.**__ \n\nIf you get an `Authorization Error` such as `Error 403: access_denied`, make sure that you are signed in with an email that has access to the application (contact the bot owner if uncertain — this is in the Gmail API configuration instructions).",
            color=await ctx.embed_color()
        ))

        # Wait for authorization code from user
        try:
            msg = await self.bot.wait_for("message", check=MessagePredicate.same_context(ctx=ctx), timeout=300)
        except asyncio.TimeoutError:
            return await ctx.send("The operation has timed out. Please try again.")

        # Complete authorization, fetch access/refresh tokens, validate credentials
        try:
            await self._run_async(flow.fetch_token, code=msg.content)
            if not flow.credentials.valid:
                raise ValueError
        except Exception:  # oauthlib.oauth2.rfc6749.errors.InvalidGrantError from flow.fetch_token, ValueError thrown above or from flow.credentials
            return await ctx.send("Error validating authorization code. Please try again.")

        # Save credentials string to config
        await self.config.guild(ctx.guild).credentials.set(flow.credentials.to_json())

        # Send confirmation
        return await ctx.send("Email authorization successful!")

    @_email_verification.command(name="reaction")
    async def _reaction(self, ctx: commands.Context, message: typing.Optional[discord.Message], emoji: typing.Union[discord.PartialEmoji, str] = None):
        """Set a reaction on a message to prompt verification when pressed (leave both blank to remove)."""

        # Clear config
        if not message and not emoji:
            await self.config.guild(ctx.guild).reaction.clear()
            return await ctx.send("The EmailVerification reaction setting was cleared!")

        # Check that both exist
        if not message or not emoji:
            return await ctx.send("Please provide both a message and an emoji.")

        # Test reaction
        try:
            await message.add_reaction(emoji)
        except discord.HTTPException:
            return await ctx.send("There was an error adding the reaction to the specified message.")

        # Save to config
        async with self.config.guild(ctx.guild).reaction() as config:
            config["channel"] = message.channel.id
            config["message"] = message.id
            config["emoji"] = emoji.id if emoji.is_custom_emoji() else emoji.name

        # Update cache
        self.reaction_cache[ctx.guild.id] = {
            "channel": message.channel.id,
            "message": message.id,
            "emoji": emoji.id if (isinstance(emoji, discord.PartialEmoji) and emoji.is_custom_emoji()) else emoji
        }

        return await ctx.tick()

    @_email_verification.command(name="logchannel")
    async def _log_channel(self, ctx: commands.Context, channel: discord.TextChannel):
        """Set the log channel for successful verifications."""
        await self.config.guild(ctx.guild).log_channel.set(channel.id)
        return await ctx.tick()

    @_email_verification.command(name="errormessage")
    async def _error_message(self, ctx: commands.Context, *, message: str = ""):
        """Set the error message to be displayed for unallowed email domains (leave blank for default)."""
        await self.config.guild(ctx.guild).domain_error.set(message)
        if not message:
            await ctx.send(f"The default error will be used: {INVALID_DOMAIN}")
        return await ctx.tick()

    @_email_verification.group(name="templates", invoke_without_command=True)
    async def _templates(self, ctx: commands.Context):
        """Set the template message to be emailed to users for verification."""
        settings = await self.config.guild(ctx.guild).templates()
        await ctx.send(embed=discord.Embed(
            title="EmailVerification Templates",
            description=f"**Subject:** {settings['subject'] or f'Default: {DEFAULT_SUBJECT}'}\n**Content:** {settings['content'] or f'Default: {DEFAULT_CONTENT}'}",
            color=await ctx.embed_color()
        ))
        await ctx.send_help()

    @_templates.command(name="subject")
    async def _templates_subject(self, ctx: commands.Context, *, subject: str = ""):
        """
        Set the template email subject (leave blank to use default).

        The following are valid placeholders:
        - `{server}` — server name
        - `{code}` — verification code
        - `{email}` — user's input email
        - `{user}` — user's username#disc
        """
        await self.config.guild(ctx.guild).templates.subject.set(subject)
        return await ctx.tick()

    @_templates.command(name="content")
    async def _templates_content(self, ctx: commands.Context, *, content: str = ""):
        """
        Set the template email content (leave blank to use default)

        The following are valid placeholders:
        - `{server}` — server name
        - `{code}` — verification code
        - `{email}` — user's input email
        - `{user}` — user's username#disc
        """
        if "{code}" not in content:
            return await ctx.send("The template must include `{code}` to be replaced with the verification code!")
        await self.config.guild(ctx.guild).templates.content.set(content)
        return await ctx.tick()

    @_email_verification.command(name="timeout")
    async def _timeout(self, ctx: commands.Context, minutes: int = 5):
        """Set amount of time given to users to enter the verification code."""
        await self.config.guild(ctx.guild).timeout.set(minutes)
        return await ctx.tick()

    @_email_verification.group(name="domains")
    async def _domains(self, ctx: commands.Context):
        """EmailVerification Domain Settings"""

    @_domains.group(name="allowed", invoke_without_command=True)
    async def _domains_allowed(self, ctx: commands.Context):
        """Email Domain Allowlist"""
        settings = await self.config.guild(ctx.guild).domains.allowed()
        await ctx.send(embed=discord.Embed(
            title="EmailVerification Domains Allowed",
            description=humanize_list([f"`{d}`" for d in settings]) or "None",
            color=await ctx.embed_color()
        ))
        await ctx.send_help()

    @_domains_allowed.command(name="add", require_var_positional=True)
    async def _domains_allowed_add(self, ctx: commands.Context, *domains: str):
        """
        Add to the list of allowed email domains.

        Enter as many domains as desired, separated by spaces (examples of domains below):
        - `domain.com` matches emails that end in @domain.com
        - `sub.domain.com` matches emails that end in @sub.domain.com
        - `*.domain.com` matches emails that are either @domain.com or @anything.domain.com
        """
        if not all([DOMAIN_REGEX.fullmatch(d) for d in domains]):
            return await ctx.send("Please make sure all entered domains are valid.")
        async with self.config.guild(ctx.guild).domains() as domain_settings:
            domain_settings["allowed"] = list(set(domain_settings["allowed"] + list(domains)))
        return await ctx.tick()

    @_domains_allowed.command(name="remove", aliases=["delete"], require_var_positional=True)
    async def _domains_allowed_remove(self, ctx: commands.Context, *domains: str):
        """
        Remove from the list of allowed email domains.

        Enter as many domains as desired, separated by spaces (examples of domains below):
        - `domain.com` matches emails that end in @domain.com
        - `sub.domain.com` matches emails that end in @sub.domain.com
        - `*.domain.com` matches emails that are either @domain.com or @anything.domain.com
        """
        if not all([DOMAIN_REGEX.fullmatch(d) for d in domains]):
            return await ctx.send("Please make sure all entered domains are valid.")
        async with self.config.guild(ctx.guild).domains() as domain_settings:
            domain_settings["allowed"] = [d for d in domain_settings["allowed"] if d not in domains]
        return await ctx.tick()

    @_domains.group(name="blocked", invoke_without_command=True)
    async def _domains_blocked(self, ctx: commands.Context):
        """Email Domain Blocklist"""
        settings = await self.config.guild(ctx.guild).domains.blocked()
        await ctx.send(embed=discord.Embed(
            title="EmailVerification Domains Blocked",
            description=humanize_list([f"`{d}`" for d in settings]) or "None",
            color=await ctx.embed_color()
        ))
        await ctx.send_help()

    @_domains_blocked.command(name="add", require_var_positional=True)
    async def _domains_blocked_add(self, ctx: commands.Context, *domains: str):
        """
        Add to the list of blocked email domains.

        Enter as many domains as desired, separated by spaces (examples of domains below):
        - `domain.com` matches emails that end in @domain.com
        - `sub.domain.com` matches emails that end in @sub.domain.com
        - `*.domain.com` matches emails that are either @domain.com or @anything.domain.com
        """
        if not all([DOMAIN_REGEX.fullmatch(d) for d in domains]):
            return await ctx.send("Please make sure all entered domains are valid.")
        async with self.config.guild(ctx.guild).domains() as domain_settings:
            domain_settings["blocked"] = list(set(domain_settings["blocked"] + list(domains)))
        return await ctx.tick()

    @_domains_blocked.command(name="remove", aliases=["delete"], require_var_positional=True)
    async def _domains_blocked_remove(self, ctx: commands.Context, *domains: str):
        """
        Remove from the list of blocked email domains.

        Enter as many domains as desired, separated by spaces (examples of domains below):
        - `domain.com` matches emails that end in @domain.com
        - `sub.domain.com` matches emails that end in @sub.domain.com
        - `*.domain.com` matches emails that are either @domain.com or @anything.domain.com
        """
        if not all([DOMAIN_REGEX.fullmatch(d) for d in domains]):
            return await ctx.send("Please make sure all entered domains are valid.")
        async with self.config.guild(ctx.guild).domains() as domain_settings:
            domain_settings["blocked"] = [d for d in domain_settings["blocked"] if d not in domains]
        return await ctx.tick()

    @_email_verification.group(name="roles")
    async def _roles(self, ctx: commands.Context):
        """EmailVerification Role Settings"""

    @_roles.group(name="added", invoke_without_command=True)
    async def _added_roles(self, ctx: commands.Context):
        """Added Roles Upon Verification"""
        settings = await self.config.guild(ctx.guild).roles.add()
        desc = ""
        for domain, roles in settings.items():
            desc += f"`{domain}`: {' '.join([r.mention for i in roles if (r := ctx.guild.get_role(i))])}\n"
        await ctx.send(embed=discord.Embed(
            title="EmailVerification Added Roles",
            description=desc or "None",
            color=await ctx.embed_color()
        ))
        await ctx.send_help()

    @_added_roles.command(name="add", require_var_positional=True)
    async def _added_roles_add(self, ctx: commands.Context, domain_or_all: str, *roles: discord.Role):
        """
        Add to the list of added roles upon verification.

        Enter either the domain or the word `all`, for example:
        - `all` matches all domains
        - `domain.com` matches emails that end in @domain.com
        - `sub.domain.com` matches emails that end in @sub.domain.com
        - `*.domain.com` matches emails that are either @domain.com or @anything.domain.com
        """
        if domain_or_all.lower() != "all" and not DOMAIN_REGEX.fullmatch(domain_or_all):
            return await ctx.send("Please enter a valid domain or `all`.")
        async with self.config.guild(ctx.guild).roles.add() as added_roles:
            added_roles[domain_or_all] = list(set(added_roles.get(domain_or_all, []) + [r.id for r in roles]))
        return await ctx.tick()

    @_added_roles.command(name="remove", aliases=["delete"], require_var_positional=True)
    async def _added_roles_remove(self, ctx: commands.Context, domain_or_all: str, *roles: discord.Role):
        """
        Remove from the list of added roles upon verification.

        Enter either the domain or the word `all`, for example:
        - `all` matches all domains
        - `domain.com` matches emails that end in @domain.com
        - `sub.domain.com` matches emails that end in @sub.domain.com
        - `*.domain.com` matches emails that are either @domain.com or @anything.domain.com
        """
        if domain_or_all.lower() != "all" and not DOMAIN_REGEX.fullmatch(domain_or_all):
            return await ctx.send("Please enter a valid domain or `all`.")
        async with self.config.guild(ctx.guild).roles.add() as added_roles:
            added_roles[domain_or_all] = [r for r in added_roles.get(domain_or_all, []) if r not in [r.id for r in roles]]
            if not added_roles[domain_or_all]:
                del added_roles[domain_or_all]
        return await ctx.tick()

    @_roles.group(name="removed", invoke_without_command=True)
    async def _removed_roles(self, ctx: commands.Context):
        """Removed Roles Upon Verification"""
        settings = await self.config.guild(ctx.guild).roles.remove()
        desc = ""
        for domain, roles in settings.items():
            desc += f"`{domain}`: {' '.join([r.mention for i in roles if (r := ctx.guild.get_role(i))])}\n"
        await ctx.send(embed=discord.Embed(
            title="EmailVerification Removed Roles",
            description=desc or "None",
            color=await ctx.embed_color()
        ))
        await ctx.send_help()

    @_removed_roles.command(name="add", require_var_positional=True)
    async def _removed_roles_add(self, ctx: commands.Context, domain_or_all: str, *roles: discord.Role):
        """
        Add to the list of removed roles upon verification.

        Enter either the domain or the word `all`, for example:
        - `all` matches all domains
        - `domain.com` matches emails that end in @domain.com
        - `sub.domain.com` matches emails that end in @sub.domain.com
        - `*.domain.com` matches emails that are either @domain.com or @anything.domain.com
        """
        if domain_or_all.lower() != "all" and not DOMAIN_REGEX.fullmatch(domain_or_all):
            return await ctx.send("Please enter a valid domain or `all`.")
        async with self.config.guild(ctx.guild).roles.remove() as removed_roles:
            removed_roles[domain_or_all] = list(set(removed_roles.get(domain_or_all, []) + [r.id for r in roles]))
        return await ctx.tick()

    @_removed_roles.command(name="remove", aliases=["delete"], require_var_positional=True)
    async def _removed_roles_remove(self, ctx: commands.Context, domain_or_all: str, *roles: discord.Role):
        """
        Remove from the list of removed roles upon verification.

        Enter either the domain or the word `all`, for example:
        - `all` matches all domains
        - `domain.com` matches emails that end in @domain.com
        - `sub.domain.com` matches emails that end in @sub.domain.com
        - `*.domain.com` matches emails that are either @domain.com or @anything.domain.com
        """
        if domain_or_all.lower() != "all" and not DOMAIN_REGEX.fullmatch(domain_or_all):
            return await ctx.send("Please enter a valid domain or `all`.")
        async with self.config.guild(ctx.guild).roles.remove() as removed_roles:
            removed_roles[domain_or_all] = [r for r in removed_roles.get(domain_or_all, []) if r not in [r.id for r in roles]]
            if not removed_roles[domain_or_all]:
                del removed_roles[domain_or_all]
        return await ctx.tick()

    @_roles.group(name="allowed", invoke_without_command=True)
    async def _roles_allowed(self, ctx: commands.Context):
        """Verification Role Allowlist"""
        settings = await self.config.guild(ctx.guild).roles.allowed()
        await ctx.send(embed=discord.Embed(
            title="EmailVerification Roles Allowed",
            description=" ".join([r.mention for i in settings if (r := ctx.guild.get_role(i))]) or "None",
            color=await ctx.embed_color()
        ))
        await ctx.send_help()

    @_roles_allowed.command(name="add", require_var_positional=True)
    async def _roles_allowed_add(self, ctx: commands.Context, *roles: discord.Role):
        """Add to the list of roles allowed to verify their emails."""
        async with self.config.guild(ctx.guild).roles() as role_settings:
            role_settings["allowed"] = list(set(role_settings["allowed"] + [r.id for r in roles]))
        return await ctx.tick()

    @_roles_allowed.command(name="remove", aliases=["delete"], require_var_positional=True)
    async def _roles_allowed_remove(self, ctx: commands.Context, *roles: discord.Role):
        """Remove from list of roles allowed to verify their emails."""
        async with self.config.guild(ctx.guild).roles() as role_settings:
            role_settings["allowed"] = [r for r in role_settings["allowed"] if r not in [r.id for r in roles]]
        return await ctx.tick()

    @_roles.group(name="blocked", invoke_without_command=True)
    async def _roles_blocked(self, ctx: commands.Context):
        """Verification Role Blocklist"""
        settings = await self.config.guild(ctx.guild).roles.blocked()
        await ctx.send(embed=discord.Embed(
            title="EmailVerification Roles Blocked",
            description=" ".join([r.mention for i in settings if (r := ctx.guild.get_role(i))]) or "None",
            color=await ctx.embed_color()
        ))
        await ctx.send_help()

    @_roles_blocked.command(name="add", require_var_positional=True)
    async def _roles_blocked_add(self, ctx: commands.Context, *roles: discord.Role):
        """Add to the list of roles disallowed from verifying their emails."""
        async with self.config.guild(ctx.guild).roles() as role_settings:
            role_settings["blocked"] = list(set(role_settings["blocked"] + [r.id for r in roles]))
        return await ctx.tick()

    @_roles_blocked.command(name="remove", aliases=["delete"], require_var_positional=True)
    async def _roles_blocked_remove(self, ctx: commands.Context, *roles: discord.Role):
        """Remove from the list of roles disallowed from verifying their emails."""
        async with self.config.guild(ctx.guild).roles() as role_settings:
            role_settings["blocked"] = [r for r in role_settings["blocked"] if r not in [r.id for r in roles]]
        return await ctx.tick()

    @_email_verification.command(name="view")
    async def _view(self, ctx: commands.Context):
        """View the EmailVerification settings."""
        settings = await self.config.guild(ctx.guild).all()
        desc = f"""
        **Authorization:** {'Complete' if (await self._get_guild_credentials(settings["credentials"])) else 'Incomplete'}
        **Domains Allowed/Blocked:** see `{ctx.clean_prefix}emailverification domains` subcommands
        **Roles to Add/Remove:** see `{ctx.clean_prefix}emailverification roles` subcommands
        **Roles Allowed/Blocked:** see `{ctx.clean_prefix}emailverification roles` subcommands
        **Email Templates:** see `{ctx.clean_prefix}emailverification templates`
        **Log Channel:** {(channel.mention if (channel := ctx.guild.get_channel(settings['log_channel'])) else None) if settings['log_channel'] else None}
        **Timeout:** {settings['timeout']} minutes
        **Domain Error Message:** {settings['domain_error'] or None}
        """
        embed: discord.Embed = discord.Embed(
            title="EmailVerification Settings",
            description=desc,
            color=await ctx.embed_color()
        )
        await ctx.send(embed=embed)
