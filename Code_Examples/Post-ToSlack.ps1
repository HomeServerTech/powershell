Param(
        [Parameter(Mandatory = $true,HelpMessage = 'Chat message')][ValidateNotNullorEmpty()]
        [String]$Message,
        [Parameter(Mandatory = $false,HelpMessage = 'Slack channel')][ValidateNotNullorEmpty()]
        [String]$Channel = "#api_testing",
        [Parameter(Mandatory = $false,HelpMessage = 'Optional name for the bot')]
        [String]$BotName = "Secret Squirrel bot",
        [Parameter(Mandatory = $false,HelpMessage = 'Optional emoji for the bot')]
        [String]$BotEmoji = ":squirrel:"
        [Parameter(Mandatory = $false,HelpMessage = 'Slack API token')]
        [String]$token = "<API_token>"
    )

function Post-ToSlack {
<# 
    .Synopsis
       Post a message to Slack
    .DESCRIPTION
        Using webhook to post to a specific slakc channel.
    .EXAMPLE
       Post-ToSlack -channel '#devops' -botname ''
    .INPUTS
        channel, use single quotes with a '#channelname' or '@username'
        botname, use single quotes, can be whatever you like.
        botemoji, use single quotes, can be whatever you like.
        message, use single quotes, variables should be able to be passed in with this message, like from the pipeline.
    .NOTES
        Single quotes are a good idea, maybe.
#>
    Param(
        [Parameter(Mandatory = $true,HelpMessage = 'Chat message')][ValidateNotNullorEmpty()]
        [String]$Message,
        [Parameter(Mandatory = $false,HelpMessage = 'Slack channel')][ValidateNotNullorEmpty()]
        [String]$Channel = "#api_testing",
        [Parameter(Mandatory = $false,HelpMessage = 'Optional name for the bot')]
        [String]$BotName = "Secret Squirrel bot",
        [Parameter(Mandatory = $false,HelpMessage = 'Optional emoji for the bot')]
        [String]$BotEmoji = ":squirrel:"
        [Parameter(Mandatory = $false,HelpMessage = 'Slack API token')]
        [String]$token = "<API_token>"
    )

Set-StrictMode -Version Latest

#Slack webhook URL.
$uri = "https://hooks.slack.com/services/$token"

    $payload = @{
	       "channel" = "$Channel";
          "username" = "$BotName";
	    "icon_emoji" = "$BotEmoji";
	          "text" = "$Message"; 
    }

Invoke-WebRequest -Uri $uri -Method "POST" -Body (ConvertTo-Json -Compress -InputObject $payload)
}

Post-ToSlack -Message $Message -Channel $Channel -BotName $BotName -BotEmoji $BotEmoji
