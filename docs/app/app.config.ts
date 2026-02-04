export default defineAppConfig({
  docus: {
    name: "bwssh",
    description: "Bitwarden-backed SSH agent for Linux",
    url: "https://github.com/reidond/bwssh",
    socials: {
      github: "reidond/bwssh",
    },
  },
  ui: {
    colors: {
      primary: "emerald",
      neutral: "slate",
    },
    pageHero: {
      slots: {
        title: "font-display text-4xl sm:text-6xl tracking-tight",
      },
    },
    pageSection: {
      slots: {
        title: "font-display tracking-tight",
      },
    },
  },
})
