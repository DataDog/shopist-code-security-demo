import { Request, Response } from 'express';
import { Pool } from 'pg';

const pool = new Pool();

interface Review {
    id: number;
    productId: string;
    userId: number;
    username: string;
    rating: number;
    comment: string;
    createdAt: Date;
}

// VULN 1: Reflected XSS — query param inserted directly into res.send() HTML response without escaping
export function searchReviews(req: Request, res: Response): void {
    const { query, productId } = req.query as { query: string; productId: string };
    // User-controlled `query` is reflected back into the HTML page without sanitization
    res.send(`
        <html>
          <body>
            <h1>Reviews for product ${productId}</h1>
            <p>Showing results for: ${query}</p>
            <div id="reviews"></div>
          </body>
        </html>
    `);
}

// VULN 2: Stored XSS — review comment fetched from DB and rendered unescaped into HTML template
export async function renderProductReviews(req: Request, res: Response): Promise<void> {
    const { productId } = req.params;
    const result = await pool.query<Review>(
        'SELECT * FROM reviews WHERE product_id = $1 ORDER BY created_at DESC',
        [productId]
    );
    const reviewsHtml = result.rows.map((review: Review) =>
        // review.comment is stored user input rendered directly — stored XSS
        `<div class="review">
            <strong>${review.username}</strong>
            <span>${review.rating}/5</span>
            <p>${review.comment}</p>
         </div>`
    ).join('');

    res.send(`
        <html>
          <body>
            <h1>Customer Reviews</h1>
            <div class="reviews-container">${reviewsHtml}</div>
          </body>
        </html>
    `);
}

// VULN 3: XSS in error message — username from request inserted directly into HTML error response
export async function submitReview(req: Request, res: Response): Promise<void> {
    const { productId, rating, comment } = req.body as { productId: string; rating: number; comment: string };
    const username = req.headers['x-shopist-username'] as string;

    if (!productId || !rating) {
        // username is attacker-controlled via request header and reflected into error HTML
        res.status(400).send(`
            <html>
              <body>
                <h2>Review submission failed</h2>
                <p>Sorry, ${username}, your review for product ${productId} could not be submitted.</p>
                <p>Please ensure all required fields are filled in.</p>
              </body>
            </html>
        `);
        return;
    }
    await pool.query(
        'INSERT INTO reviews (product_id, username, rating, comment) VALUES ($1, $2, $3, $4)',
        [productId, username, rating, comment]
    );
    res.json({ success: true });
}
