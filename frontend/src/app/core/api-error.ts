import { HttpErrorResponse } from '@angular/common/http';

export interface ApiErrorMessage {
  message: string;
  retryAt?: number;
}

const conflicts: Record<string, string> = {
  'Target not verified': 'Vérifiez la propriété du site avant de lancer un scan.',
  'Scan already active': 'Un scan est déjà en cours pour ce site. Consultez son historique.',
  'Email already registered': 'Cette adresse e-mail est déjà utilisée.',
  'Domain already registered': 'Ce domaine figure déjà dans vos sites.',
  'Scan is not done': 'Le rapport sera disponible à la fin du scan.',
};

export function translateApiError(error: unknown, now = Date.now()): ApiErrorMessage {
  if (!(error instanceof HttpErrorResponse)) {
    return { message: 'Une erreur inattendue est survenue. Réessayez.' };
  }
  const detail: unknown = error.error?.detail;
  switch (error.status) {
    case 0:
      return { message: 'Impossible de joindre le serveur. Vérifiez votre connexion.' };
    case 400: {
      const expected =
        typeof detail === 'string' ? /^Expected TXT record at ([^:]+): (.+)$/.exec(detail) : null;
      return {
        message: expected
          ? `Propriété non prouvée. Publiez un TXT au nom ${expected[1]} avec la valeur ${expected[2]}, puis réessayez après sa propagation.`
          : 'La demande est invalide. Vérifiez les informations saisies.',
      };
    }
    case 401:
      return {
        message:
          detail === 'Invalid email or password'
            ? 'Adresse e-mail ou mot de passe incorrect.'
            : 'Votre session a expiré. Reconnectez-vous.',
      };
    case 404:
      return { message: 'Ce site ou ce scan est introuvable.' };
    case 409:
      return {
        message: conflicts[String(detail)] ?? 'Cette action est temporairement impossible.',
      };
    case 422:
      return {
        message:
          'Vérifiez les champs : e-mail valide, mot de passe de 12 à 128 caractères, domaine ou URL HTTP(S) sans identifiants ni port inhabituel.',
      };
    case 429: {
      const header = error.headers.get('Retry-After');
      const seconds = header && /^\d+$/.test(header.trim()) ? Number(header) : NaN;
      const date = header ? Date.parse(header) : NaN;
      const retryAt = Number.isFinite(seconds) ? now + seconds * 1000 : date;
      return {
        message: 'Un scan a été demandé trop récemment. Patientez avant de réessayer.',
        ...(Number.isFinite(retryAt) ? { retryAt: Math.max(now, retryAt) } : {}),
      };
    }
    case 503:
      return { message: 'Le service est temporairement indisponible. Réessayez dans un instant.' };
    default:
      return { message: 'Le serveur a rencontré une erreur. Réessayez plus tard.' };
  }
}
