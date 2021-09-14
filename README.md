# COMING SOON NOT READY OMG IF YOU RUN THIS AND IT EATS YOUR DOG ITS NOT MY FAULT

<div align="center">
<img src="./Group3r-Banner.png" alt="Group3r Banner">
by Mike Loss (@mikeloss)

with help from @LukeHealy, @Sh3r4, and @LegendOfLynkle


Development of Group3r was generously supported by my previous employer:
  <img src="https://user-images.githubusercontent.com/24580473/124420224-bd3fbf00-dd91-11eb-9ac6-936e6992bd38.png" data-canonical-src="https://user-images.githubusercontent.com/24580473/124420224-bd3fbf00-dd91-11eb-9ac6-936e6992bd38.png" width="300"/>
</div>

## OK BUT WTF IS IT DO?

Like its ancestors, Group3r is a tool for pentesters and red teamers to rapidly enumerate relevant settings in AD Group Policy, and to identify exploitable misconfigurations in same. It does this by talking LDAP to Domain Controllers, parsing GPO config files off the domain SYSVOL share, and also by looking at other files that are referenced within GPOs, like scripts, MSI packages, exes, etc.

It might also be useful for other people doing other stuff, but it is explicitly NOT meant to be an audit tool. If you want to check your policy configs against some particular standard, you probably want Microsoft's Security and Compliance Toolkit, not Group3r.

I'll say it again extra clear: Group3r is *even more* focused on being useful for attackers and *even less* of an audit tool than previous iterations.

## Y U MAKE IT???

A lot of offensive tradecraft around Group Policy has historically focused on two main things: finding passwords (in GPP passwords etc), and abusing weak ACLs to modify GPOs. This stuff is super useful, but if you ignore the rest of Group Policy you're leaving a huge amount of really useful information on the table, never mind some really fun attack paths.

## Y U MAKE IT AGAIN???

Group3r is a page-1 rewrite of Grouper2, which was in turn a page-1 rewrite of Grouper. 

Grouper(1) was written in PowerShell and had a lot of horrible limitations.

Grouper2 was written in C# by someone who didn't know how classes worked and accidentally reinvented them from first principles by shoving wads of JSON around the place. That someone may have been me.

Group3r was also written in C# but this time by someone who has learned a small number of things about programming (like what a class is) and that person may also be me.

If I've done it right, it should be a lot more useful, a lot friendlier, and a lot less brittle than Grouper2 was.

## Y U MAKE ME SCROLL THIS FAR FOR USAGE???

Because I'm a monster.

Ideally, run it on a domain joined machine as a domain user. 

If you want, you can use it with `runas /netonly` on a non-domain-joined computer, but you'll need to (at least) tell it where to find a DC with `-c`, and you'll probably also want to tell it what domain to enumerate with `-d`. If you do this but don't have your machine's DNS pointed at a DC or some other appropriate DNS server for the environment, a bunch of the checks probably won't work properly. Don't say I didn't warn you.

### Output options
`-s` to send results to stdout.

`-f group3r.log` to send results to a file.

If you don't choose either -s or -f it will not run at all.

`-w` to limit output to only show settings with an associated 'finding', i.e. something significant enough that I wrote code to go looking for it.

`-a 4` to limit output to only the highest severity findings. You could probably also use some smaller numbers too I guess. Like 1, or 3. Probably not 0, that would be weird. 

## WHAT HAPPENED TO PRETTY MODE???

It was a fucken nightmare to write the first time and have half as much free time as I did back then.

Also it used to truncate data all the time.