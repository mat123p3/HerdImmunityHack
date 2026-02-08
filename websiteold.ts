// Website (Base Class)

export class Website {
  protected storedUrl: string
  protected rankings: number[] = []

  constructor(url: string) {
    this.storedUrl = url
  }

  addReview(rating: number): void {
    if (rating >= 1 && rating <= 5) {
      this.rankings.push(rating)
    }
  }

  get url(): string {
    return this.storedUrl
  }

  get totalReviews(): number {
    return this.rankings.length
  }

  get averageRating(): number {
    if (this.rankings.length === 0) return 0
    const sum = this.rankings.reduce((a, b) => a + b, 0)
    return sum / this.rankings.length
  }
}

// RankedWebsite (derived class)
// may have compatibility issues with backend rating functions. amend as necessary

export class RankedWebsite extends Website {
  private rankingPercentage = 0
  private urlColor = "Gray"

  calculateRanking(): void {
    this.rankingPercentage = (this.averageRating / 5) * 100

    if (this.rankingPercentage < 20) {
      this.urlColor = "Black"    // blocked
    } else if (this.rankingPercentage < 40) {
      this.urlColor = "Red"
    } else if (this.rankingPercentage < 60) {
      this.urlColor = "Orange"
    } else if (this.rankingPercentage < 80) {
      this.urlColor = "Yellow"
    } else {
      this.urlColor = "Green"
    } 
  }

  get percentage(): number {
    return this.rankingPercentage
  }

  get color(): string {
    return this.urlColor
  }

  get shouldBlock(): boolean {
    return this.urlColor === "Black"
  }
}

export class WebsiteDatabase {
  private sites = new Map<string, RankedWebsite>()

  getSite(url: string): RankedWebsite {
    if (!this.sites.has(url)) {
      this.sites.set(url, new RankedWebsite(url))
    }
    return this.sites.get(url)!
  }

  addReview(url: string, rating: number): void {
    const site = this.getSite(url)
    site.addReview(rating)
    site.calculateRanking()
  }
}

export function Basic(site: RankedWebsite): void {
  const urlEl = document.getElementById("url")!
  const ratingEl = document.getElementById("rating")!
  const colorEl = document.getElementById("color")!

  urlEl.textContent = site.url
  ratingEl.textContent = `${site.percentage.toFixed(1)}%`
  colorEl.textContent = site.color
  colorEl.className = site.color.toLowerCase()

  if (site.shouldBlock) {
    window.location.href = "https://redirect.example.com"
  }
}
