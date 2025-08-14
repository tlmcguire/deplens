import discord
from discord.ext import commands

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

@bot.slash_command(name="shutdown", description="Shuts down the bot.")
async def shutdown(ctx):
    await ctx.respond("Shutting down...")
    await bot.close()

bot.run('YOUR_TOKEN_HERE')