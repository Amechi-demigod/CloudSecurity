import type { PageInfo } from "../components/ui";

/** The (i) tip shown after each main page's title (PageHeader's `info` prop). */
export const PAGE_INFO = {
  overview: { title: "Overview", text: "A summary of your security. Admins can choose what appears here with Customize; it applies to everyone in the organisation." },
  cloudIssues: { title: "From your cloud accounts", text: "Sentrigis reads the settings of your Azure, AWS and Google Cloud accounts (read-only) and flags risky ones, like public storage or admins without multi-factor sign-in." },
  vulnerabilities: { title: "From your devices, servers and website", text: "Software found by the Sentrigis agent and by the internet scan, matched against public lists of known security flaws." },
  internetFacing: { title: "From the internet scan", text: "Sentrigis scans your verified domains and IP addresses from the internet, the way an attacker would, and lists what's exposed." },
  threats: { title: "From the Sentrigis agent", text: "Suspicious activity the agent sees on laptops and servers as it happens, such as attempts to turn off antivirus." },
  cloudResources: { title: "Your cloud", text: "Every server, database, storage account and other resource in your connected cloud accounts." },
  computers: { title: "Security of your computers", text: "Laptops, desktops and servers running the Sentrigis agent: are they updated, protected and checking in? For who owns them, see Hardware register." },
  hardware: { title: "Your hardware register", text: "Everything your company owns, agent or not: who has it, where it is, and when the warranty ends. For security status, see Computers & servers." },
  network: { title: "Your network equipment", text: "Switches, firewalls, access points and printers found by a network scan, with known flaws in their software." },
  attackSurface: { title: "Summary", text: "Whether you would pass a PCI scan today, and what to do next." },
  connections: { title: "Connections", text: "Cloud accounts, directories and alert channels Sentrigis reads from or sends to." },
  agents: { title: "Agents & updates", text: "Which Sentrigis agent version each device runs, and how new versions roll out." },
  notifications: { title: "Notifications", text: "Rules for who is told about what, by email or Teams." },
  people: { title: "People & approvals", text: "Who can sign in, what they can do, and risky actions waiting for a second person." },
  audit: { title: "Audit log", text: "A record of every action, by people and by Sentrigis." },
} satisfies Record<string, PageInfo>;
