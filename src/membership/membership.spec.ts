import { jest } from '@jest/globals';
import { ConfigService } from '@nestjs/config';
import { MembershipService, Member } from './membership.service';
import { ApplicationPolicyService } from '../applications/application-policy.service';
import { AuthSettings } from '../auth/auth.settings';
import { DatabaseService } from '../shared/connections/database.service';

describe('Automatic membership adapter', () => {
  const userId = '1236638c-55ab-441b-8e06-49d185573c35';
  function fixture(rows: Member[]) {
    const service = new MembershipService(new ConfigService());
    const query = jest.fn(async () => ({ rows }));
    jest
      .spyOn(
        service as unknown as { connection: () => { query: typeof query } },
        'connection',
      )
      .mockReturnValue({ query });
    return { service, query };
  }
  it('calls only the narrow function with normalized email and internal UUID', async () => {
    const f = fixture([{ id: '1', iam_subject: userId, estado: 'activo' }]);
    await f.service.linkVerifiedRafaelMember(userId, ' MEMBER@UTEM.CL ');
    expect(f.query).toHaveBeenCalledWith(
      'SELECT id::text, iam_subject, estado FROM public.iam_link_verified_rafael_member($1::uuid,$2::text)',
      [userId, 'member@utem.cl'],
    );
  });
  it('reports missing migration, insufficient grants or DB failure as infrastructure failure', async () => {
    const f = fixture([]);
    f.query.mockRejectedValue(new Error('SQL details'));
    await expect(
      f.service.linkVerifiedRafaelMember(userId, 'member@utem.cl'),
    ).rejects.toThrow('MEMBERSHIP_UNAVAILABLE');
  });
  it.each([
    { rows: [] },
    { rows: [{ id: '1', iam_subject: userId, estado: 'inactivo' }] },
    { rows: [{ id: '1', iam_subject: 'other', estado: 'activo' }] },
  ])('does not admit an absent, inactive or conflicting link', async ({ rows }) => {
    const f = fixture(rows);
    const policy = new ApplicationPolicyService(
      {} as DatabaseService,
      new AuthSettings(new ConfigService({ AUTH_APPLICATION_CODE: 'rafael' })),
      f.service,
    );
    await expect(
      policy.linkRafaelMember('member@utem.cl', userId),
    ).rejects.toThrow('ACCESS_NOT_ENABLED');
  });
});
