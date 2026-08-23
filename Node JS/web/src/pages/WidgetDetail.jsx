import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { useAuth } from '../AuthContext';

export default function WidgetDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const [widget, setWidget] = useState(null);
  const [quantity, setQuantity] = useState(1);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  const [reviews, setReviews] = useState([]);
  const [averageRating, setAverageRating] = useState(null);
  const [reviewCount, setReviewCount] = useState(0);
  const [reviewError, setReviewError] = useState('');
  const [reviewRating, setReviewRating] = useState(5);
  const [reviewBody, setReviewBody] = useState('');
  const [editingReviewId, setEditingReviewId] = useState(null);

  useEffect(() => {
    api
      .widgets()
      .then((all) => setWidget(all.find((w) => String(w.id) === id) || null))
      .catch((err) => setError(err.message));
    // The list endpoint is reused here for simplicity; a dedicated
    // GET /api/widgets/:id call would work identically.
  }, [id]);

  function loadReviews() {
    api
      .widgetReviews(id)
      .then((data) => {
        setReviews(data.reviews);
        setAverageRating(data.average_rating);
        setReviewCount(data.review_count);
      })
      .catch((err) => setReviewError(err.message));
  }

  useEffect(loadReviews, [id]);

  const myReview = user ? reviews.find((r) => r.user_id === user.id) : null;

  async function addToCart() {
    if (!user) return navigate('/login');
    try {
      await api.addToCart(Number(id), Number(quantity));
      setMessage('Added to cart.');
    } catch (err) {
      setError(err.message);
    }
  }

  function startEdit(review) {
    setEditingReviewId(review.id);
    setReviewRating(review.rating);
    setReviewBody(review.body || '');
    setReviewError('');
  }

  function cancelEdit() {
    setEditingReviewId(null);
    setReviewRating(5);
    setReviewBody('');
  }

  async function submitReview(e) {
    e.preventDefault();
    setReviewError('');
    try {
      if (editingReviewId) {
        await api.updateReview(editingReviewId, { rating: Number(reviewRating), body: reviewBody });
      } else {
        await api.addReview(id, { rating: Number(reviewRating), body: reviewBody });
      }
      cancelEdit();
      loadReviews();
    } catch (err) {
      setReviewError(err.message);
    }
  }

  async function removeReview(reviewId) {
    try {
      if (user.role === 'admin') {
        await api.adminDeleteReview(reviewId);
      } else {
        await api.deleteReview(reviewId);
      }
      if (editingReviewId === reviewId) cancelEdit();
      loadReviews();
    } catch (err) {
      setReviewError(err.message);
    }
  }

  if (!widget) return <p>Loading...</p>;

  return (
    <div className="card" style={{ maxWidth: 640 }}>
      <div className="widget-thumb" style={{ height: 180, borderRadius: 'var(--radius-md)', fontSize: '3rem', marginBottom: '1.25rem' }}>
        {widget.name.slice(0, 1).toUpperCase()}
      </div>
      <h1>{widget.name}</h1>
      <p>{widget.description}</p>
      <p className="widget-price">${(widget.price_cents / 100).toFixed(2)}</p>
      <span className={`badge ${widget.stock_quantity > 0 ? 'in-stock' : 'out-of-stock'}`}>
        {widget.stock_quantity > 0 ? `${widget.stock_quantity} in stock` : 'Out of stock'}
      </span>
      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', marginTop: '1.25rem' }}>
        <input type="number" min="1" value={quantity} onChange={(e) => setQuantity(e.target.value)} />
        <button onClick={addToCart} disabled={widget.stock_quantity < 1}>
          Add to cart
        </button>
      </div>
      {message && <p className="helper-text" style={{ marginTop: '0.75rem' }}>{message}</p>}
      {error && <p className="error" style={{ marginTop: '0.75rem' }}>{error}</p>}

      <hr style={{ margin: '1.5rem 0' }} />

      <h2>Reviews</h2>
      <p className="helper-text">
        {reviewCount > 0
          ? `${'★'.repeat(Math.round(averageRating))}${'☆'.repeat(5 - Math.round(averageRating))} ${averageRating.toFixed(1)} average (${reviewCount} review${reviewCount === 1 ? '' : 's'})`
          : 'No reviews yet.'}
      </p>

      {user && user.role === 'customer' && !myReview && editingReviewId === null && (
        <form onSubmit={submitReview} style={{ marginTop: '1rem' }}>
          <label>
            Rating
            <select value={reviewRating} onChange={(e) => setReviewRating(e.target.value)}>
              {[5, 4, 3, 2, 1].map((n) => (
                <option key={n} value={n}>
                  {n} star{n === 1 ? '' : 's'}
                </option>
              ))}
            </select>
          </label>
          <textarea
            placeholder="Share your thoughts on this widget..."
            value={reviewBody}
            onChange={(e) => setReviewBody(e.target.value)}
            style={{ display: 'block', width: '100%', marginTop: '0.5rem' }}
          />
          <button type="submit" style={{ marginTop: '0.5rem' }}>
            Submit review
          </button>
        </form>
      )}

      {editingReviewId !== null && (
        <form onSubmit={submitReview} style={{ marginTop: '1rem' }}>
          <label>
            Rating
            <select value={reviewRating} onChange={(e) => setReviewRating(e.target.value)}>
              {[5, 4, 3, 2, 1].map((n) => (
                <option key={n} value={n}>
                  {n} star{n === 1 ? '' : 's'}
                </option>
              ))}
            </select>
          </label>
          <textarea
            value={reviewBody}
            onChange={(e) => setReviewBody(e.target.value)}
            style={{ display: 'block', width: '100%', marginTop: '0.5rem' }}
          />
          <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
            <button type="submit">Save changes</button>
            <button type="button" className="secondary" onClick={cancelEdit}>
              Cancel
            </button>
          </div>
        </form>
      )}

      {reviewError && <p className="error" style={{ marginTop: '0.75rem' }}>{reviewError}</p>}

      <div style={{ marginTop: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        {reviews.map((review) => (
          <div key={review.id} className="card">
            <strong>{'★'.repeat(review.rating)}{'☆'.repeat(5 - review.rating)}</strong>
            <p style={{ margin: '0.5rem 0' }}>{review.body}</p>
            <p className="helper-text">
              {review.full_name} &middot; {new Date(review.created_at).toLocaleDateString()}
            </p>
            {user && (user.id === review.user_id || user.role === 'admin') && (
              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
                {user.id === review.user_id && (
                  <button type="button" className="secondary" onClick={() => startEdit(review)}>
                    Edit
                  </button>
                )}
                <button type="button" className="secondary" onClick={() => removeReview(review.id)}>
                  Delete
                </button>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
